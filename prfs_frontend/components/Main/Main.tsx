import React from 'react';
import axios from 'axios';
import styles from './Main.module.css'
import ProofSummary from '@/components/ProofSummary/ProofSummary';

const Main = () => {
  let [list, setList] = React.useState<any>([]);

  React.useEffect(() => {
    setList([1, 2, 3]);
  }, []);

  const handleClickGenProof = React.useCallback(() => {
    console.log(111);;
    axios.get('http://localhost::4000')
  }, []);

  let contents = list.map((elem: any) => {
    return (
      <ProofSummary className={styles.proofSummary}>
        power
      </ProofSummary>
    )
  });

  return (
    <div className={styles.wrapper}>
      <div className={styles.inner}>
        <div className={styles.left}>
          <button onClick={handleClickGenProof}>Generate proof</button>
        </div>
        <div className={styles.right}>
          <div className={styles.proofsLabel}>Proofs</div>
          <div>
            {contents}
          </div>
        </div>
      </div>
    </div>
  );
};

export default Main;
