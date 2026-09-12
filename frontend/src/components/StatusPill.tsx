export function StatusPill({status}:{status:string}){return <span className={`pill ${status.toLowerCase().replace('_','-')}`}>{status.replace('_',' ')}</span>}
