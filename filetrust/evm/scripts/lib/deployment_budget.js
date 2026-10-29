// Conservative deployment debit reservations, saved BEFORE RPC broadcast.
// Failed/uncertain broadcasts keep their reservation. A partial deployment
// needs operator review; rerunning must not silently obtain a fresh allowance.
import fs from 'node:fs';
import {Transaction} from 'ethers';

const CAP=16777216n;
function integer(value,label) {
  if(typeof value!=='string' || !/^(?:0x[0-9a-fA-F]+|[0-9]+)$/.test(value))
    throw new Error(`Explicit non-negative ${label} required`);
  return BigInt(value);
}

export function deploymentBudget({maximumWei,address,journal,chainId}) {
  const maximum=integer(maximumWei,'FILETRUST_DEPLOY_MAX_DEBIT_WEI');
  if(maximum<=0n)throw new Error('Deployment debit allowance must be positive');
  const fd=fs.openSync(journal,'wx',0o600);
  const write=row=>{fs.writeSync(fd,JSON.stringify(row)+'\n');fs.fsyncSync(fd);};
  let reserved=0n;
  const signedReservations=new Set();
  write({kind:'allowance',address:address.toLowerCase(),maximum_wei:String(maximum)});
  return {
    reserveRpc(method,params) {
      if(method!=='eth_sendTransaction' && method!=='eth_sendRawTransaction')return;
      let tx=params?.[0];
      let signedHash;
      if(method==='eth_sendRawTransaction'){
        let signed;
        try{signed=Transaction.from(tx);}catch{throw new Error('Invalid signed deployment transaction');}
        if(!signed.isSigned() || chainId==null || signed.chainId!==BigInt(chainId))
          throw new Error('Signed deployment transaction belongs to another chain');
        signedHash=signed.hash;
        tx={from:signed.from,gas:String(signed.gasLimit),value:String(signed.value),nonce:signed.nonce,
          ...(signed.maxFeePerGas!=null?{maxFeePerGas:String(signed.maxFeePerGas)}:{gasPrice:String(signed.gasPrice)})};
      }
      if(!tx || tx.from?.toLowerCase()!==address.toLowerCase())throw new Error('Unapproved deployment signer');
      if(signedHash && signedReservations.has(signedHash))return;
      const gas=integer(tx.gas,'transaction gas limit');
      const price=integer(tx.maxFeePerGas??tx.gasPrice,'transaction fee ceiling');
      const value=integer(tx.value??'0','transaction value');
      if(gas<=0n || gas>CAP || price<=0n)throw new Error('Deployment gas/fee bound is invalid');
      const debit=gas*price+value;
      if(reserved+debit>maximum)throw new Error('Deployment debit allowance exhausted before broadcast; review the existing journal');
      reserved+=debit;
      write({kind:'reservation',nonce:tx.nonce??null,hash:signedHash??null,maximum_debit_wei:String(debit),reserved_wei:String(reserved)});
      if(signedHash)signedReservations.add(signedHash);
    },
    close(){fs.closeSync(fd);},
    reservedWei(){return reserved;},
  };
}

export function guardSignedDeploymentBroadcast(provider,budget,onSigned=()=>{}) {
  // Hardhat's ethers adapter may send raw bytes directly to its underlying
  // transport instead of calling provider.send. Guard this entry point too.
  const broadcast=provider.broadcastTransaction.bind(provider);
  provider.broadcastTransaction=async raw=>{
    budget.reserveRpc('eth_sendRawTransaction',[raw]);
    onSigned(raw);
    return broadcast(raw);
  };
}
