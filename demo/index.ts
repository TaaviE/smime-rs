import * as smime from "../pkg";

const boot = async () => {
  const form = document.getElementById("emlForm") as HTMLFormElement;
  const textarea = document.getElementById("emlInput") as HTMLTextAreaElement;
  const resultEl = document.getElementById("result") as HTMLDivElement;
  const jsonOutput = document.getElementById("jsonOutput") as HTMLTextAreaElement;

  const setResult = (msg: string, ok: boolean | null = null) => {
    resultEl.textContent = String(msg);
    if (ok === true) {
      resultEl.style.color = "#0a7a0a";
    } else if (ok === false) {
      resultEl.style.color = "#b00020";
    } else {
      resultEl.style.color = "inherit";
    }
  };

  form.addEventListener("submit", (e: Event) => {
    e.preventDefault();
    const eml = textarea.value || "";
    if (!eml) {
      setResult("Please paste .eml content first.", false);
      return;
    }
    setResult("Verifying...");
    try {
      console.debug(eml);
      const result: smime.SmimeValidationResult = smime.verify_smime_from_eml(eml.replaceAll("\n", "\r\n"));
      console.debug(result);
      let valid = false;
      for (const signer of result.signers) {
         if (signer.signature_valid) {
           valid = true;
           break;
         }
      }
      setResult(`Verification result: ${valid ? "VALID" : "INVALID"}`, valid);

      const toPlainObject = (obj: any): any => {
        if (obj === null || typeof obj !== "object") return obj;
        if (obj instanceof Date) return obj;
        if (Array.isArray(obj)) return obj.map(toPlainObject);
        if (obj instanceof Uint8Array) return Array.from(obj);

        const plain: any = {};
        let curr = obj;
        while (curr && curr !== Object.prototype) {
          Object.getOwnPropertyNames(curr).forEach(prop => {
            if (prop !== "constructor" && !prop.startsWith("__wbg_ptr") && !prop.startsWith("__destroy") && prop !== "free") {
              try {
                const val = obj[prop];
                if (typeof val !== "function") {
                  plain[prop] = toPlainObject(val);
                }
              } catch (e) {
              }
            }
          });
          curr = Object.getPrototypeOf(curr);
        }
        return plain;
      };
      jsonOutput.value = JSON.stringify(toPlainObject(result), null, 2);
    } catch (err: any) {
      console.error(err);
      setResult(`Error: ${err && err.message ? err.message : String(err)}`, false);
    }
  });
};

boot();
