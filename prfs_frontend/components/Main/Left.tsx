import React from "react";
import axios from "axios";

import styles from "./Left.module.scss";

const Left = (props: any) => {
  const [proof, setProof] = React.useState("");

  const handleClickGenProof = React.useCallback(async () => {
    const fetchData = async () => {
      if (window.ethereum !== undefined) {
        const accounts = await window.ethereum.request({
          method: "eth_requestAccounts",
        });
        if (accounts != null && Array.isArray(accounts)) {
          let account = accounts[0];
          const exampleMessage = "proof";

          try {
            const from = account;
            const msg = `0x${Buffer.from(exampleMessage, "utf8").toString(
              "hex"
            )}`;
            const sig = await window.ethereum.request({
              method: "personal_sign",
              params: [msg, from, "password"],
            });

            console.log(11, sig);

            let { data } = await axios.post("http://localhost:4000/gen_proof", {
              addr: account,
              sig,
            });

            console.log(44, data);
            setProof(data.proof.join(", "));
          } catch (err) {
            console.error(err);
            // personalSign.innerHTML = `Error: ${err.message}`;
          }
        }
      }

      // let data2 = web3.utils.keccak256("0");
      // let sig = await web3.eth.sign(data2, account);
      // console.log(11, sig);

      // let { data } = await axios.post("http://localhost:4000/gen_proof", {
      //   addr: account,
      //   sig,
      // });

      // console.log(11, data);
    };

    fetchData().then((_res) => {});
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
