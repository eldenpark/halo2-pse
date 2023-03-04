import React from 'react';
import axios from 'axios';
import styles from './Left.module.css';

const Left = () => {
  const handleClickGenProof = React.useCallback(async () => {
    console.log(111);;

    let a = await axios.get('http://localhost:4000');
    console.log(11, a);

  }, []);

  return (
    <div className={styles.wrapper}>
      <div className={styles.leftLabel}></div>
      <button onClick={handleClickGenProof}>Generate proof</button>
      <div className={styles.desc}>
        Currently the only proof we support generating is <i>Asset proof</i>
      </div>
    </div>
  );
};

export default Left;
