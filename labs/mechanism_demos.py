"""Small mechanism experiments. These are NOT Juice Shop exploit results."""
import base64
import hashlib
import hmac
import json
import sqlite3
import tempfile
import time
from pathlib import Path


def sqlite_demo():
    db=sqlite3.connect(":memory:")
    db.execute("CREATE TABLE users(id INTEGER, email TEXT)")
    db.executemany("INSERT INTO users VALUES (?,?)",[(1,"a@lab.invalid"),(2,"b@lab.invalid")])
    malicious="' OR 1=1-- "
    vulnerable=db.execute("SELECT id FROM users WHERE email = '"+malicious+"'").fetchall()
    safe=db.execute("SELECT id FROM users WHERE email = ?",(malicious,)).fetchall()
    normal=db.execute("SELECT id FROM users WHERE email = ?",("a@lab.invalid",)).fetchall()
    db.close()
    assert len(vulnerable)==2 and safe==[] and normal==[(1,)]
    return {"vulnerable_rows":len(vulnerable),"parameterized_rows":len(safe),"normal_rows":len(normal)}


def access_demo():
    baskets={1:{"owner":"A","marker":"A_ONLY"},2:{"owner":"B","marker":"B_ONLY"}}
    vulnerable=baskets[2]["marker"]
    safe=baskets[2]["marker"] if baskets[2]["owner"]=="A" else None
    own=baskets[1]["marker"] if baskets[1]["owner"]=="A" else None
    assert vulnerable=="B_ONLY" and safe is None and own=="A_ONLY"
    return {"cross_owner_vulnerable":vulnerable,"cross_owner_fixed":safe,"own_fixed":own}


def path_demo():
    with tempfile.TemporaryDirectory() as tmp:
        root=Path(tmp);base=root/"public";base.mkdir()
        (base/"note.txt").write_text("PUBLIC",encoding="utf8")
        (root/"marker.txt").write_text("PRIVATE_LAB_MARKER",encoding="utf8")
        candidate=(base/"../marker.txt").resolve()
        observed=candidate.read_text(encoding="utf8")
        allowed=candidate.is_relative_to(base.resolve())
        normal=(base/"note.txt").resolve().is_relative_to(base.resolve())
        assert observed=="PRIVATE_LAB_MARKER" and not allowed and normal
        return {"vulnerable_read":observed,"fixed_allows_outside":allowed,"fixed_allows_inside":normal}


def jwt_demo():
    # Teaching HMAC example, not a replacement for a maintained JWT library.
    key=b"LAB_ONLY_NOT_A_PRODUCTION_SECRET"
    enc=lambda obj:base64.urlsafe_b64encode(json.dumps(obj,separators=(",",":")).encode()).rstrip(b"=")
    header=enc({"alg":"HS256","typ":"JWT"})
    claims={"sub":"lab-a","iss":"local-lab","aud":"juicesec-demo","exp":int(time.time())+60}
    payload=enc(claims);message=header+b"."+payload
    signature=base64.urlsafe_b64encode(hmac.new(key,message,hashlib.sha256).digest()).rstrip(b"=")
    token=message+b"."+signature
    def verifies(candidate):
        a,b,c=candidate.split(b".")
        expected=base64.urlsafe_b64encode(hmac.new(key,a+b"."+b,hashlib.sha256).digest()).rstrip(b"=")
        return hmac.compare_digest(expected,c)
    claims["sub"]="lab-b";tampered=header+b"."+enc(claims)+b"."+signature
    assert verifies(token) and not verifies(tampered)
    return {"original_signature_valid":verifies(token),"tampered_signature_valid":verifies(tampered),
            "limit":"Signature mechanism only; not a complete JWT verifier"}


if __name__=="__main__":
    result={"scope":"Independent mechanism demos; not Juice Shop","sqlite":sqlite_demo(),
            "access_control":access_demo(),"path":path_demo(),"jwt":jwt_demo()}
    out=Path(__file__).resolve().parents[1]/"evidence"/"mechanism-demos.json"
    out.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf8")
    print(json.dumps(result,ensure_ascii=False,indent=2))
