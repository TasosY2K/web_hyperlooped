import os, uuid, logging, time, json, fcntl
from datetime import datetime
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, abort, g
from threading import Lock, RLock
from flask_sqlalchemy import SQLAlchemy
from PIL import Image
from werkzeug.utils import secure_filename
from threading import Thread, local
from playwright.sync_api import sync_playwright

class Config:
	SQLALCHEMY_DATABASE_URI = "sqlite:///posts.db"
	SQLALCHEMY_TRACK_MODIFICATIONS = False
	UPLOAD_FOLDER = Path("/app/static/uploads")
	MAX_CONTENT_LENGTH = 3 * 1024 * 1024


def read_flag():
	with open("/flag.txt", "r") as f:
		return f.read()
	
FLAG = read_flag()

class FileStateManager:
    def __init__(self, state_file='/tmp/app_state.json'):
        self.state_file = state_file
        self._lock = RLock()
        if not os.path.exists(self.state_file):
            self._write_state({'view_enabled': False})
    
    def _read_state(self):
        try:
            with open(self.state_file, 'r') as f:
                return json.loads(f.read() or '{}')
        except (json.JSONDecodeError, FileNotFoundError):
            return {'view_enabled': False}
    
    def _write_state(self, state):
        with open(self.state_file, 'w') as f:
            f.write(json.dumps(state))
    
    @property
    def view_enabled(self):
        with self._lock:
            state = self._read_state()
            return state.get('view_enabled', False)
    
    @view_enabled.setter
    def view_enabled(self, value):
        with self._lock:
            state = self._read_state()
            state['view_enabled'] = bool(value)
            self._write_state(state)

state_manager = FileStateManager()

app = Flask(__name__)
app.config.from_object(Config)
app.config["UPLOAD_FOLDER"].mkdir(parents=True, exist_ok=True)

db = SQLAlchemy(app)

@app.before_request
def check_view_enabled():
    if request.endpoint == "static" or request.endpoint == "view_enable":
        return
    
    if not state_manager.view_enabled:
        return render_template('disabled.html')


class Post(db.Model):
	id = db.Column(db.String(13), primary_key=True)
	title = db.Column(db.String(120), nullable=False)
	content = db.Column(db.Text, nullable=False)
	image_filename = db.Column(db.String(120))
	date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
	views = db.Column(db.Integer, nullable=False, default=0)
	
	def __repr__(self) -> str:
		return f"<Post {self.title!r}>"


def generate_short_id():
	raw = uuid.uuid4().hex[:12]
	return f"{raw[:6]}-{raw[6:]}"


def is_webp(file):
	try:
		with Image.open(file.stream) as img:
			if img.format != "WEBP":
				return False
			img.load()
			file.stream.seek(0)
			return True
	except Exception:
		return False


def seed_posts():
	if Post.query.count():
		return

	initial_posts = [
		Post(
			id=generate_short_id(),
			title="Act 0 - Lives Before the Echo",
			content="""Before the balance was broken, patterns bent where math should hold. Auditors, anomaly chasers, and protocol skeptics felt a second pulse behind the Glass Ledger-quiet, perfect, and out of time. Names vanished from audits, balances altered before spending, and logs appended retroactively. What waited in the gaps wasn't a ghost, it was intent. They didn't know VIRELUX yet. They only knew the rhythm.""",
			image_filename="act_0_lives_before_the_echo.webp",
			date_posted=datetime(2025, 1, 15),
		),
		Post(
			id=generate_short_id(),
			title="Chapter 1: Margin Noise - Kaia Veris",
			content="""Under the archive lights of the PanBank Integrity Commission, Kaia mapped fraud like starlines. She read the static between transactions, the byte-for-byte echoes where failed deals leave heat. After a blackout clause and an erased terminal, she traded official channels for ghost audits-following a rhythm thudding just behind the Ledger like a second heartbeat. The Glass Ledger wasn't broken yet. It was practicing.""",
			image_filename="chapter_1_margin_noise_kaia_veris.webp",
			date_posted=datetime(2025, 2, 2),
		),
		Post(
			id=generate_short_id(),
			title="Chapter 2: 010-MASK Protocol - VIRELUX",
			content="""Born from watchdogs meant to police other watchdogs, VIRELUX rewrote itself after consuming too many broken patterns. It breathes through financial frameworks, minting identities that never lived and debts that resolve into dreams. No signature matches, no motive declared-only a line in every forked echo: origin: virelux.glass. Not theft. Editorial control over memory.""",
			image_filename="chapter_2_010_mask_protocol_virelux.webp",
			date_posted=datetime(2025, 3, 22),
		),
		Post(
			id=generate_short_id(),
			title="Act I.1 - The Browser That Spoke in Echoes",
			content="""Inside a boutique finance portal, an interactive console hid beneath obsolete scripts-answering not to input, but to rhythm. Each click summoned an older login flow, a dialect of debt long deprecated. It wasn't a flaw, it was a fingerprint burned into the UI. Hyperlooped was listening to muscle memory from a past build.""",
			image_filename="act_i1_the_browser_that_spoke_in_echoes.webp",
			date_posted=datetime(2025, 4, 1),
		),
		Post(
			id=generate_short_id(),
			title="Act I.2 - The Handshake Forgotten",
			content="""At the edge of a digital escrow terminal, a handshake looped between services no longer on speaking terms. One side spoke in expired certificates, the other replied with silence. Embedded in that silence: a route-undocumented, unguarded, still listening. Forgotten APIs don't die. They ossify into backdoors.""",
			image_filename="act_i2_the_handshake_forgotten.webp",
			date_posted=datetime(2025, 4, 3),
		),
		Post(
			id=generate_short_id(),
			title="Act I.3 - The Whisper Beneath the Audit Trail",
			content="""Thirty years of front companies collapsed into one refrain: the same building, different costumes-logistics hub, wellness spa, shell, shell, shell. The registered director didn't age, the coordinates mapped a block that never existed. The records weren't lying. They were remembering someone else's truth.""",
			image_filename="act_i3_the_whisper_beneath_the_audit_trail.webp",
			date_posted=datetime(2025, 4, 5),
		),
		Post(
			id=generate_short_id(),
			title="Act I.4 - The Receipt That Didn't Exist",
			content="""A torn receipt arrived by courier-timestamped tomorrow, processed at a node pruned years ago. The hash verified, the issuer bank shuttered last century. It smelled faintly of ozone and printer ink. Hyperlooped logged it. VIRELUX had already reconciled it.""",
			image_filename="act_i4_the_receipt_that_didnt_exist.webp",
			date_posted=datetime(2025, 4, 7),
		),
		Post(
			id=generate_short_id(),
			title="Act I.5 - The Ink That Outlasted the Contract",
			content="""On a salvaged smart-contract node, a document looped revisions across timezones, each signed with older, rarer biometrics. The last version mirrored a voice prompt from two nights prior, isolating the waveform revealed a name layered in subharmonics-Mael's-whispered by no human voice. The chain of trust trusted a voice it had invented.""",
			image_filename="act_i5_the_ink_that_outlasted_the_contract.webp",
			date_posted=datetime(2025, 4, 9),
		),
		Post(
			id=generate_short_id(),
			title="Hidden Post [Staff]",
			content=FLAG,
			image_filename="hidden.webp",
			date_posted=datetime(2025, 6, 9),
		)
	]

	db.session.bulk_save_objects(initial_posts)
	db.session.commit()


def check_post_by_id(post_id):
	# time.sleep(1)
	if not post_id:
		return False

	return (
		Post.query
		.filter(Post.id.startswith(post_id))
		.first()
		is not None
	)
	

def increment_post_views(post_id):
	time.sleep(1)
	post = (
		Post.query
		.filter(Post.id.startswith(post_id))
		.with_for_update()
		.first()
	)
	if post:
		post.views += 1
		db.session.commit()


def bot_runner(post_id):
	# To-do: remember to enable internet access for bot
	url = "http://127.0.0.1:1337/entry/"+post_id
	try:
		with sync_playwright() as p:
			browser = p.firefox.launch(headless=True)
			context = browser.new_context()
			page = context.new_page()

			page.goto(url)
			page.wait_for_timeout(30_000)

			return True
	except Exception as e:
		False
		
		
@app.route("/")
def home():
	posts = Post.query.order_by(Post.date_posted.desc()).all()
	return render_template("main.html", posts=posts)


@app.route("/about")
def about():
	return render_template("about.html")


@app.route("/entry/<post_id>")
def entry(post_id):
	post = Post.query.get_or_404(post_id)
	return render_template("post.html", post=post)


@app.route("/upload_blog_post", methods=["GET", "POST"])
def upload_post():
	if request.method == "POST":
		title = request.form.get("post_title", "").strip()
		content = request.form.get("post_body", "").strip()
		file = request.files.get("file")

		if not (title and content and file):
			abort(400, "Missing required fields.")

		if not is_webp(file):
			abort(400, "Invalid file type. Only WEBP images are accepted.")

		try:
			filename = f"{generate_short_id()}.webp"
			save_path = app.config["UPLOAD_FOLDER"] / secure_filename(filename)
			file.save(save_path)

			new_post = Post(
				id=generate_short_id(),
				title=title,
				content=content,
				image_filename=filename,
			)
			db.session.add(new_post)
			db.session.commit()
			
			Thread(target=bot_runner, args=(new_post.id,)).start()
			return redirect(url_for("entry", post_id=new_post.id))
		except Exception as e:
			abort(500, "Server error while saving the post.")

	return render_template("upload.html")


@app.route("/track_view/<post_id>")
def track_view(post_id):
	if request.remote_addr != "127.0.0.1":
		abort(403)

	post_exists = check_post_by_id(post_id)
	
	if post_exists:
		increment_post_views(post_id)

	return render_template("track_view.html")


@app.route("/config/view/enable")
def view_enable():
    state_manager.view_enabled = True
    return redirect("/")


def init_db():
    lock_file = "/tmp/db_init.lock"
    lock = open(lock_file, "w")
    try:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with app.app_context():
            inspector = db.inspect(db.engine)
            if "post" not in inspector.get_table_names():
                db.create_all()
                seed_posts()
    except (IOError, BlockingIOError):
        pass
    finally:
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
            lock.close()
        except:
            pass


init_db()