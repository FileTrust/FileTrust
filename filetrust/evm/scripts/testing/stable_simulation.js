import { definePlugin } from 'hardhat/plugins';

// Keep automatic estimation and mining in the same EDR pending-block context.
// With same-timestamp blocks enabled, wall-clock rollover can turn a no-op
// timestamp SSTORE into a changed-value SSTORE after gas was already estimated.
// This never increases gas, changes a transaction, or touches an HTTP network.
export async function stableSimulationHooks() {
  const pending = new WeakMap();
  const snapshots = new WeakMap();
  const internalControl = new WeakSet();
  return {
    async onRequest(context, connection, request, next) {
      if (connection.networkConfig.type !== 'edr-simulated') {
        return next(context, connection, request);
      }
      if (internalControl.has(connection) && request.method === 'evm_setNextBlockTimestamp') {
        return next(context, connection, request);
      }
      const provider = connection.provider;
      const arm = async plan => {
        internalControl.add(connection);
        try {
          await provider.request({ method: 'evm_setNextBlockTimestamp', params: [Number(BigInt(plan.timestamp))] });
        } finally {
          internalControl.delete(connection);
        }
        pending.set(connection, plan);
      };
      if (request.method === 'evm_snapshot') {
        const result = await next(context, connection, request);
        if (result.error === undefined) {
          let saved = snapshots.get(connection);
          if (saved === undefined) snapshots.set(connection, saved = new Map());
          saved.set(result.result, pending.get(connection));
        }
        return result;
      }
      if (request.method === 'evm_revert') {
        const result = await next(context, connection, request);
        if (result.result === true) {
          const saved = snapshots.get(connection);
          const plan = saved?.get(request.params[0]);
          if (plan === undefined) pending.delete(connection);
          else pending.set(connection, plan);
          let discard = false;
          for (const id of saved?.keys() ?? []) {
            if (id === request.params[0]) discard = true;
            if (discard) saved.delete(id);
          }
        }
        return result;
      }
      if (request.method === 'evm_setNextBlockTimestamp') {
        const result = await next(context, connection, request);
        if (result.error === undefined) {
          const parent = await provider.request({ method: 'eth_getBlockByNumber', params: ['latest', false] });
          pending.set(connection, { parent: parent.hash, timestamp: request.params[0], synthetic: false });
        }
        return result;
      }
      if (request.method === 'evm_increaseTime') {
        const plan = pending.get(connection);
        const result = await next(context, connection, request);
        if (result.error === undefined && plan?.synthetic) {
          const parent = await provider.request({ method: 'eth_getBlockByNumber', params: ['latest', false] });
          if (parent.hash === plan.parent) {
            // Failed estimation leaves our next-block override armed. Advance
            // that synthetic override too, so it cannot suppress a time jump.
            const target = BigInt(plan.timestamp) + BigInt(request.params[0]);
            await arm({ ...plan, timestamp: target < BigInt(parent.timestamp) ? parent.timestamp : `0x${target.toString(16)}` });
          } else pending.delete(connection);
        }
        return result;
      }
      if (request.method === 'hardhat_reset') {
        const result = await next(context, connection, request);
        if (result.error === undefined) {
          pending.delete(connection);
          snapshots.delete(connection);
        }
        return result;
      }
      const estimate = request.method === 'eth_estimateGas';
      const send = request.method === 'eth_sendTransaction' || request.method === 'eth_sendRawTransaction';
      const blockTag = request.params?.[1];
      // An explicitly historical/latest estimation tag retains its own semantics.
      if ((!estimate && !send) || (estimate && blockTag !== undefined && blockTag !== 'pending')) {
        return next(context, connection, request);
      }
      if (!await provider.request({ method: 'hardhat_getAutomine', params: [] })) {
        // A prior failed estimate may still have a synthetic override armed.
        // Retain its origin so explicit time controls remain correct in manual
        // mode too; a new parent hash invalidates it when mining completes.
        return next(context, connection, request);
      }
      const parent = await provider.request({ method: 'eth_getBlockByNumber', params: ['latest', false] });
      let plan = pending.get(connection);
      if (plan === undefined || plan.parent !== parent.hash) {
        const block = await provider.request({ method: 'eth_getBlockByNumber', params: ['pending', false] });
        plan = { parent: parent.hash, timestamp: block.timestamp, synthetic: true };
        pending.set(connection, plan);
      }
      // Use the timestamp EDR has already selected, honoring explicit time
      // increases/deadlines. Re-read after mining, reset, or snapshot restoration.
      await arm(plan);
      return next(context, connection, request);
    },
  };
}

export default definePlugin({
  id: 'filetrust-stable-simulation',
  hookHandlers: { network: async () => ({ default: stableSimulationHooks }) },
});
