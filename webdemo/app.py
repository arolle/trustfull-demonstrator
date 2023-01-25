import uuid
import base64
import io
import json
import logging
import mimetypes
import os
import requests
from functools import wraps
from hashlib import sha256
from itertools import islice
from operator import itemgetter
from urllib.parse import urlparse

from flask import Flask, render_template, request, send_file, redirect, flash, url_for, make_response
from flask_wtf.csrf import CSRFProtect

from .bytetree import ByteTree

mimetypes.add_type("application/wasm", ".wasm")

# list of encrypted votes
# set of user ids that have voted (also obtainable from SIGNATURES)
VOTED_IDS = set()
# dictionary assigning session id to signature reference
SIGN_REFS = dict()

def get_auth_server_url():
    parsed_url = urlparse(os.getenv('AUTH_SERVER_URL'))

    if parsed_url.port is None:
        return f'{parsed_url.scheme}://{parsed_url.hostname}'
    
    return f'{parsed_url.scheme}://{parsed_url.hostname}:{parsed_url.port}'


app = Flask(__name__)
app.config["SECRET_KEY"] = os.urandom(32)
app.debug = True
csrf = CSRFProtect(app)

FILENAME = "data.txt"
PUBLIC_KEY = os.path.join(os.path.abspath(os.path.dirname(__file__)), "publicKey")
POLL_DATA = {
    "question": "Who do you vote for?",
    "fields": ("Blue Candidate", "Green Candidate", "Yellow Candidate"),
    "publicKey": None,
}
STATS = {}
RESULTS = "results.json"
SIGNATURES = "signatures.txt"


def init_stats():
    if os.path.exists(FILENAME):
        STATS["nvotes"] = _count_lines(FILENAME)
    else:
        STATS["nvotes"] = 0


def _count_lines(filename):
    with open(filename) as f:
        return sum(1 for _ in f)


def init_pk():
    if os.path.exists(PUBLIC_KEY):
        with open(PUBLIC_KEY, "rb") as f:
            # Public key as int array, to be directly pasted in Javascript code
            POLL_DATA["publicKey"] = [int(x) for x in f.read()]


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if request.cookies.get('user') == None or not _is_authenticated(request.cookies.get('user')):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


def _check_for_signed_votes(request):
    sign_ref = get_user_sign_ref(request)
    if sign_ref is None:
        # ensure cookie is set
        response = make_response(render_template("poll.html", data=POLL_DATA, stats=STATS))
        userno = get_or_gen_userid(request)
        set_userid(response,userno)
        return response
    signature = _confirm_if_user_has_signed(sign_ref)
    if signature is None:
        flash('Waiting for signing','signing_wait')
        return render_template("poll.html", data=POLL_DATA, stats=STATS, signing_waiting=True)
    del_user_sign_ref(request)
    flash('The encrypted vote is signed and ready for submission','msg')
    return render_template("poll.html", data=POLL_DATA, stats=STATS, show_success=True, signature=signature)

# format: json array with two ByteTree elements, which each are represented as
# byte arrays (list of integers < 256)
def _append_vote_to_ciphertexts(vote):
    with open(FILENAME, "a") as f:
        print(vote, file=f)
        STATS["nvotes"] += 1


def _record_signature(signature):
    with open(SIGNATURES, "a") as f:
        f.write(f"{signature}\n")

def _has_user_already_voted(candidate_signature):
    if candidate_signature is None:
        return False
    return _get_userInfo_from_signature(candidate_signature) in VOTED_IDS

def _get_userInfo_from_signature(signature):
    jws_payload = signature.split('.')[1]
    jws_payload_decoded = base64.urlsafe_b64decode(jws_payload + '=' * (4 - len(jws_payload) % 4))
    payload_json = json.loads(jws_payload_decoded)
    return payload_json["userInfo"]

def _confirm_if_user_has_signed(sign_ref):
    r = requests.post(
        f'{get_auth_server_url()}/confirm_sign',
        json={
            'signRef': sign_ref,
        }
    )

    if r.status_code == 200:
        return r.json()['signature']

    return None


# TODO drop exemption
@csrf.exempt
@app.route("/vote_submission", methods=["POST"])
def vote_submission():
    # check if this is a vote submission
    pre_vote = request.form.get("ballot")
    vote = _validate_vote(pre_vote)

    if pre_vote and isinstance(vote, dict):
        signature = vote["signature"]
        # a list of byte arrays
        enc_vote_ba_lst = vote["vote"]
        # json encoding of above
        enc_vote_str = json.dumps(list(map((lambda x: list(bytes(x))),enc_vote_ba_lst)))
        # byte array of above
        enc_vote_ba = ByteTree(list(map((lambda x: ByteTree.from_byte_array(x)),enc_vote_ba_lst))).to_byte_array()
        if _validate_vote_auth(enc_vote_ba,signature):
            user_id = _get_userInfo_from_signature(signature)
            logging.error(user_id)
            has_voted = _has_user_already_voted(signature)
            if not user_id:
                flash('Invalid signature')
                return redirect(url_for('root'))
            if has_voted:
                logging.error(f"User {user_id} attempted to revote")
                flash('You have already voted')
                return redirect(url_for('root'))
            # add to store of votes
            _append_vote_to_ciphertexts(enc_vote_str)
            _record_signature(signature)
            VOTED_IDS.add(user_id)
            logging.error(f"{user_id} just voted successfully" )
            # confirm submission
            flash('Successful submission of encrypted vote.','success')
            return redirect(url_for('root'))
    logging.error(f"Error verifying encrypted vote and signature. Could not submit your vote.")
    flash('Error verifying encrypted vote and signature. Could not submit your vote.','error')
    return redirect(url_for('root'))

def get_userid(request):
    if 'userno' in request.cookies:
        return request.cookies.get('userno')
    else:
        return None

def get_or_gen_userid(request):
    if 'userno' in request.cookies:
        return request.cookies.get('userno')
    return str(uuid.uuid1())

def set_userid(response,userno):
    response.set_cookie('userno', userno)

def get_user_sign_ref(request):
    userno = get_userid(request)
    if not (userno is None) and userno in SIGN_REFS:
        return SIGN_REFS[userno]
    return None

def set_user_sign_ref(request,sign_ref, userno):
    SIGN_REFS[userno] = sign_ref

def del_user_sign_ref(request):
    userno = get_userid(request)
    del SIGN_REFS[userno]

# either checking for signed votes,
# or accepting hash signing requests or vote submissions
@app.route("/", methods=("GET", "POST"))
def root():
    if POLL_DATA["publicKey"] is None:
        return "Missing public key!"

    if request.method == "GET":
        # flash('You have already voted','error')
        return _check_for_signed_votes(request)

    # assume this is a signing request
    vote_hash = request.form.get("field")
    user_email = request.form.get('email-for-signing')

    error = _validate_hash256(vote_hash)
    if error:
        return error

    # ensure cookie later
    userno = get_or_gen_userid(request)
    # encrypted_vote = str(vote).encode('utf-8')
    # hashed_encryption = sha256()
    # hashed_encryption.update(encrypted_vote)
    # hex_string = hashed_encryption.digest().hex()
    beautified_hex_string = ' '.join([vote_hash[i:i+4] for i in range(0, len(vote_hash), 4)])
    logging.error(f"Hex-string: {beautified_hex_string}")

    sign_request = requests.post(
        f'{get_auth_server_url()}/init_sign',
        json={
            'email': user_email,
            'text': '',
            'vote': beautified_hex_string,
        }
    )

    if sign_request.status_code == 200:
        response_object = sign_request.json()
        signature_reference = response_object['signRef']
        # update outstanding signing request
        set_user_sign_ref(request, signature_reference, userno)
        response = make_response(render_template("poll.html", data=POLL_DATA, stats=STATS, show_success=True, hash=beautified_hex_string))
        set_userid(response,userno)
        return response

    if sign_request.status_code == 418:
        flash(sign_request.json()['message'],'msg')
        return redirect(url_for('root'))

    flash('Could not cast your vote.','error')
    return redirect(url_for('root'))



def base64urldec(string):
    padlen = 4 - len(string) % 4
    return base64.urlsafe_b64decode(string + '=' * padlen)


# get hash value from signature and validate
def _validate_vote_auth(enc_vote_ba,signature):
    hashed_encryption = sha256()
    hashed_encryption.update(enc_vote_ba)
    hash_dgst = hashed_encryption.digest()

#    with open('sample-signed-vote.json') as f:
#       sample_signed_vote = json.loads(f.read())

    parts = signature.split('.')
    if len(parts) != 3:
        return "malformed signature: expect three components in signature"
    jws_payload = parts[1]
    try:
        jws_payload_decoded = base64urldec(jws_payload)
        payload_json = json.loads(jws_payload_decoded)["signatureData"]["userSignature"]
        signed = payload_json.split('.')
        hash_val = ''.join(base64urldec(signed[1]).decode('ascii').split(' '))
        return hash_dgst.hex() == hash_val
    except Exception as e:
        return None


def _validate_hash256(vote_hash_str):
    len_hash = len(vote_hash_str)
    if len_hash != 64:
        return f"Expected hash of length 64, got {len_hash}: {vote_hash_str}"
    try:
        x = int(vote_hash_str, 16)
    except ValueError:
        return f"Expected vote hash, got {vote_hash_str}"
    return None


# returns dict with byte tree and signature string
def _validate_vote(vote):
    try:
        x = json.loads(vote)
        enc_vote = ByteTree.from_byte_array(bytes.fromhex(x["vote"]))
        nodes = enc_vote.dest_node()
        if len(nodes) != 2:
            return f"Vote format error of encrypted vote"
        enc_vote = list(map((lambda x: x.to_byte_array()), nodes))
    except json.JSONDecodeError:
        return "Vote format error (cannot decode JSON)"
    except KeyError:
        return "Vote format error (missing key: vote)"

    newdict = {k: v for k, v in x.items() if k == "signature" or k == "vote"}
    if len(newdict) != 2:
        return f"Vote format error (missing key: signature)"
    # TODO authenticate

    newdict["vote"] = enc_vote
    return newdict


def _delete_file(file):
    if os.path.exists(file):
        stat = os.stat(file)
        os.remove(file)
        return True
    return False


def _reset():
    STATS["nvotes"] = 0
    
    response_text = ""
    if _delete_file(FILENAME):
        response_text += "Successfully deleted {FILENAME}:<br/><pre>{stat}</pre>\n"
    
    if _delete_file(RESULTS):
        response_text += "Successfully deleted {RESULTS}:<br/><pre>{stat}</pre>\n"

    if _delete_file(SIGNATURES):
        response_text += "Successfully deleted {SIGNATURES}:<br/><pre>{stat}</pre>\n"

    if response_text:
        return response_text

    return "Nothing to do!"


@csrf.exempt
@app.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'GET':
        if request.cookies.get('user') != None:
            if _is_authenticated(request.cookies.get('user')):
                return redirect("/")
        return render_template("login.html")
    
    email = request.form.get("email")
    r = requests.post(
        f'{get_auth_server_url()}/init_auth',
        json={'email': email},
    )

    if r.status_code == 200:
        auth_ref = r.json()['authRef']
        res = make_response(redirect('/'))
        res.set_cookie('user', str(auth_ref))
        return res
    
    flash(str(r.text))
    return redirect(url_for("login"))


def _is_authenticated(user_identification):
    r = requests.post(
        f'{get_auth_server_url()}/authentication_validity',
        json={'authRef': user_identification}
    )

    if r.status_code == 200:
        return True
    
    return False

@csrf.exempt
@app.route("/publicKey", methods=("GET", "POST"))
def publickey():
    """
    Endpoint for the public key.

    POST: Receive the public key from the admin after the mix network generates it. Currently, no authentication is
        done. The key should be provided as an attachment in the POST request, the file name should be `publicKey`.
        Example curl call: `curl -i -X POST -F publicKey=@./publicKey <root URL>/publicKey`.
    GET: Return the current public key as an octet stream.

    This function is exempt from CSRF since it is not meant to be accessed from the web interface.
    """
    if request.method == "GET":
        if not os.path.isfile(PUBLIC_KEY):
            return "Missing public key!", 404

        return send_file(
            PUBLIC_KEY,
            mimetype="application/octet-stream",
            as_attachment=True,
            attachment_filename="publicKey",
        )

    new_pk = request.files.get("publicKey")
    if new_pk is None:
        return "publicKey missing", 400

    new_pk.save(PUBLIC_KEY)
    init_pk()
    _reset()

    return "OK"


@app.route("/ciphertexts")
def ciphertexts():
    """
    Endpoint for the encrypted cipher votes.

    Returns the current votes as a byte tree encoded as an octet stream.
    """
    if not os.path.exists(FILENAME):
        return "No ciphertexts found", 404

    with open(FILENAME) as f:
        # Read votes as received by encrypt(s) from poll.html
        vote_list = [
            (
                ByteTree.from_byte_array(x[0]),  # encrypted0
                ByteTree.from_byte_array(x[1]),  # encrypted1
            )
            for x in map(json.loads, f)
        ]
        # Convert N x 2 -> 2 x N
        left, right = tuple(zip(*vote_list))
        # Single ByteTree to hold all encrypted votes
        byte_tree = ByteTree([ByteTree(left), ByteTree(right)])

        return send_file(
            io.BytesIO(byte_tree.to_byte_array()),
            mimetype="application/octet-stream",
            download_name="ciphertexts",
            as_attachment=True,
        )


@csrf.exempt
@app.route("/results", methods=("GET", "POST"))
def results():
    """
    Endpoint for the results page.

    POST: Receive the tally from the admin after the mix net has finished executing. Currently, no authentication is
        done. Format should be a JSON dictionary candidate -> values.
    GET: Return a page with a visualization of the received results.

    This function is exempt from CSRF since it is not meant to be accessed from the web interface.
    """
    
    if request.method == "POST":
        with open(RESULTS, 'w+') as result:
            result.write(json.dumps(request.get_json()))
        return "OK"

    if not os.path.exists(RESULTS):
        return "Result file does not exist", 404

    content = None
    with open(RESULTS, 'r+') as result:
        content = json.loads(result.read())

    if content is None:
        return "Result file is empty", 404

    largest = max(content.values())
    palette = [
        "#332288",
        "#88CCEE",
        "#44AA99",
        "#117733",
        "#999933",
        "#DDCC77",
        "#CC6677",
        "#882255",
        "#AA4499",
    ]
    palette = islice(palette, len(content))
    meta = dict(
        question=POLL_DATA["question"], nvotes=sum(content.values()), largest=largest
    )
    bars = sorted(content.items(), key=itemgetter(1))
    bars = [(k, 100 * v / largest, v, color) for (k, v), color in zip(bars, palette)]
    return render_template("results.html", meta=meta, bars=bars)


init_stats()
init_pk()
if __name__ == "__main__":
    import sys

    if len(sys.argv) != 2 and sys.argv[1].lower() != "debug":
        print(
            "This application is not meant to be run directly. To force-run it in debug mode, pass the 'debug' argument:",
            sys.argv[0],
            "debug",
            file=sys.stderr,
        )

    app.run(debug=True)
