import React from "react";
import axios from "axios";
import { ethers } from 'ethers';

import styles from "./Left.module.scss";

const Left = (props: any) => {
  const [proof, setProof] = React.useState("");

  const handleClickGenProof = React.useCallback(async () => {
    const fetchData = async () => {
      let accounts = await window.ethers.send('eth_requestAccounts', []);

      if (accounts != null && Array.isArray(accounts)) {
        const account = accounts[0];
        let signer = window.ethers.getSigner();
        let msg = ethers.utils.hashMessage('temp');
        const digest = ethers.utils.arrayify(msg);

        let sig = await signer.signMessage(digest);
        let s = ethers.utils.arrayify(sig);

        let pk = ethers.utils.recoverPublicKey(digest, s);
        console.log('account', account);
        console.log('digest', digest);
        console.log('s', s);
        console.log('pk', pk);

        // let { data } = await axios.post("http://localhost:4000/gen_proof", {
        //   addr: account,
        //   sig,
        // });

      }
      //   if (window.ethereum !== undefined) {
      //     const accounts = await window.ethereum.request({
      //       method: "eth_requestAccounts",
      //     });

      //     if (accounts != null && Array.isArray(accounts)) {
      //       let account = accounts[0];
      //       const exampleMessage = "proof";

      //       try {
      //         console.log(11, sig);


      //         // let { data } = await axios.post("http://localhost:4000/gen_proof", {
      //         //   addr: account,
      //         //   sig,
      //         // });

      //         // console.log(44, data);
      //         // setProof(data.proof.join(", "));
      //       } catch (err) {
      //         console.error(err);
      //         // personalSign.innerHTML = `Error: ${err.message}`;
      //       }
      //     }
      //   }

      //   // let data2 = web3.utils.keccak256("0");
      //   // let sig = await web3.eth.sign(data2, account);
      //   // console.log(11, sig);

      //   // let { data } = await axios.post("http://localhost:4000/gen_proof", {
      //   //   addr: account,
      //   //   sig,
      //   // });

      //   // console.log(11, data);
    };

    fetchData().then((_res) => { });
  }, [setProof]);

  return (
    <div className={styles.wrapper}>
      <div className={styles.leftLabel}></div>
      <button onClick={handleClickGenProof}>Generate proof</button>
      <div className={styles.desc}>
        Currently the only proof we support generating is <i>Asset proof</i>
      </div>
      <div>{proof}</div>
    </div>
  );
};

export default Left;
