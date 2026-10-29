import fs from 'node:fs';

// A dedicated file-backed signer avoids RPC account-management APIs. Only the
// credential path enters the environment; its value never enters argv/logs.
export function configureDeploymentSigner(ethers,keyFile,fixedGasPriceWei) {
  const fd=fs.openSync(keyFile,fs.constants.O_RDONLY|fs.constants.O_NOFOLLOW|fs.constants.O_NONBLOCK);
  let raw;
  try {
    const info=fs.fstatSync(fd);
    if(!info.isFile() || info.mode&0o077 || ![0,process.getuid()].includes(info.uid) || info.size>68)
      throw new Error('Deployment key must be an owner-only regular file');
    raw=fs.readFileSync(fd,'utf8').trim();
  } finally {fs.closeSync(fd);}
  let signer;
  try {
    if(!/^(0x)?[a-fA-F0-9]{64}$/.test(raw))throw new Error();
    signer=new ethers.Wallet(raw.startsWith('0x')?raw:'0x'+raw,ethers.provider);
  } catch {throw new Error('Invalid deployment credential');}
  const price=BigInt(fixedGasPriceWei);
  if(price<=0n)throw new Error('Deployment gas price must be positive');
  const send=signer.sendTransaction.bind(signer);
  signer.sendTransaction=async request=>{
    const tx={...request};
    if(tx.gasPrice==null && tx.maxFeePerGas==null){tx.type=0;tx.gasPrice=price;}
    if(tx.gasLimit==null){
      const estimate=await ethers.provider.estimateGas({...tx,from:signer.address});
      const margin=(estimate*6n+4n)/5n;
      tx.gasLimit=margin>16777216n?16777216n:margin;
    }
    return send(tx);
  };
  const deploy=ethers.deployContract.bind(ethers),at=ethers.getContractAt.bind(ethers);
  const factory=ethers.getContractFactory.bind(ethers);
  ethers.getSigners=async()=>[signer];
  ethers.deployContract=(name,args=[],options={})=>deploy(name,args,{...options,signer});
  ethers.getContractAt=(name,address,selected=signer)=>at(name,address,selected);
  ethers.getContractFactory=(name,options={})=>factory(name,{...options,signer});
  return signer;
}
