from flask import Flask, render_template, redirect, url_for, request ,flash, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from sqlalchemy import Column, Integer, String
from sqlalchemy import update
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_bootstrap import Bootstrap
from werkzeug.utils import secure_filename
from flask_wtf import FlaskForm 
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from sqlalchemy.exc import IntegrityError
import datetime
import os
from datetime import datetime
from slugify import slugify
import psycopg2


app = Flask(__name__)

db = SQLAlchemy()


#########Configration##############
basedir = os.path.dirname((os.path.abspath(__file__)))

app.config['SECRET_KEY'] = "hdkfhskjfhsdkjfhsdkfhsdkhf763487236"

app.config['SQLALCHEMY_DATABASE_URI'] = "postgresql://blog:amit@1234@localhost:5432/blog_db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


db = SQLAlchemy(app)
migrate = Migrate(app, db)

 
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

app.config['UPLOAD_FOLDER'] = basedir+"/static/uploads/blog"
app.config['PROFILE_FOLDER'] = basedir+"/static/uploads/profile"


########End#Configration##############

##########################models######################################
class Sign_up(UserMixin, db.Model):
    __tablename__='sign_up'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(255), nullable=True)
    email = db.Column(db.String(255),nullable=True)
    password = db.Column(db.String(80))
    login_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.Boolean, default=False, nullable=False)



class About(db.Model):
    __tablename__='about'
    id = db.Column(db.Integer, primary_key=True)
    image = db.Column(db.Text(),nullable=True)
    about_meta_description = db.Column(db.Text(),nullable=True)
    about_meta_keywords = db.Column(db.Text(),nullable=True)
    about_title = db.Column(db.Text(),nullable=True)
    name = db.Column(db.Text(),nullable=True)
    about_me = db.Column(db.Text(),nullable=True)
    num = db.Column(db.Text(),nullable=True) 
    email = db.Column(db.Text(),nullable=True)
    uploded_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.Boolean, default=False, nullable=False)

class Category(db.Model):
    __tablename__ = 'category'
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(255),nullable=True)
    status = db.Column(db.Boolean, default=False, nullable=False)


class Index(db.Model):
    __tablename__ = 'index'
    id = db.Column(db.Integer, primary_key=True)
    index_meta_description = db.Column(db.Text(),nullable=True)
    index_meta_keywords = db.Column(db.Text(),nullable=True)
    index_title = db.Column(db.Text(),nullable=True)
    status = db.Column(db.Boolean, default=False, nullable=False)
    

class Contact(db.Model):
    __tablename__='contact'

    id = db.Column(db.Integer,primary_key=True)
    Name = db.Column(db.Text(),nullable=True)
    Email= db.Column(db.Text(),nullable=True)
    Subject = db.Column(db.Text(),nullable=True)
    Message = db.Column(db.Text(),nullable=True)
    contact_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.Boolean, default=False, nullable=False)


class Posts(db.Model):
    __tablename__='posts'

    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.Text(),nullable=True)
    blog_meta_description = db.Column(db.Text(),nullable=True)
    blog_meta_keywords = db.Column(db.Text(),nullable=True)
    blog_title = db.Column(db.Text(),nullable=True)
    slug = db.Column(db.Text(),unique=True,nullable=True)
    textarea = db.Column(db.Text(),nullable=True)
    image = db.Column(db.Text(),nullable=True)
    posted_at = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.Boolean, default=False, nullable=False)

    
    @staticmethod
    def generate_slug(target, value, oldvalue, initiator):
        if value and (not target.slug or value != oldvalue):
            target.slug = slugify(value)



db.event.listen(Posts.blog_title, 'set', Posts.generate_slug, retval=False)


########################End models#########################################



@app.route('/')
@app.route('/home/')
def index():
    page = request.args.get('page', 1, type=int)
    category = Posts.query.filter_by(status='False').paginate(page=page, per_page=1)
    pro = About.query.filter_by(status='False').all()
    index = Index.query.all()
    return render_template('home/index.html',category=category,pro=pro,index=index)
####################
@app.route('/blog-detail/<slug>/')
def post_detail(slug):
    blog = Posts.query.filter_by(status='False',slug=slug)
    for i in blog:
        category = i.category
    related_post = Posts.query.filter_by(status='False',category=category)
    pro = About.query.filter_by(status='False')
    return render_template('post/blog_detail.html',data=blog,pro=pro,related_post=related_post)
#######################

###################Dashboard##############################
@login_manager.user_loader
def load_user(user_id):
    return Sign_up.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])



@app.route('/admin-login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = Sign_up.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('backend_dashboard'))
        error = 'Invalid username or password'
        return render_template('login/admin-login.html', form=form,error=error)
    return render_template('login/admin-login.html', form=form)

@app.route('/admin-login-signup/', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = Sign_up(username=form.username.data, email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        db.session.close()
        return '<h1>New user has been created!</h1>'
    return render_template('login/signup.html', form=form)

@app.route('/logout-blog-url-admin/')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/adminurl-login/')
@login_required
def backend_dashboard():
    return render_template('backend_dashboard/index.html')


@app.route('/view-blogs/')
def view_blogs():
    blog = Posts.query.filter_by(status=False)
    return render_template('post/viewblog.html', blog=blog)


@app.route('/add-about-me/', methods=['GET','POST'])
@login_required
def add_about():
    if request.method == 'POST':
        about_meta_description = request.form['about_meta_description']
        about_meta_keywords = request.form['about_meta_keywords']
        about_title = request.form['about_title']
        name = request.form['name']
        about_me = request.form['editor1']
        num = request.form['num']
        email = request.form['email']
        image = request.files['profile']
        filename = secure_filename(image.filename)
        path = '/static/uploads/profile/'+filename
        image.save(os.path.join(app.config['PROFILE_FOLDER'],filename))            
        entry = About(about_meta_description=about_meta_description,about_meta_keywords=about_meta_keywords,about_title=about_title,name=name,about_me=about_me,num=num,email=email,image=path)
        db.session.add(entry)
        db.session.commit()
        db.session.close()
        return redirect('/add-about-me/')
    else:
        a = About.query.all()
    return render_template('about/add_about.html',a=a)

@app.route('/update-about-me/<int:id>/', methods=['GET','POST'])
@login_required
def update_about_me(id):
    if request.method == 'POST':
        about_meta_description = request.form['about_meta_description']
        about_meta_keywords = request.form['about_meta_keywords']
        about_title = request.form['about_title']
        name = request.form['name']
        about_me = request.form['editor1']
        num = request.form['num']
        email = request.form['email']
        image = request.files['profile']
        filename = secure_filename(image.filename)
        path = '/static/uploads/profile/'+filename
        image.save(os.path.join(app.config['PROFILE_FOLDER'],filename))
        ch = About.query.filter_by(id=id).update(dict(about_meta_description=about_meta_description,about_meta_keywords=about_meta_keywords,about_title=about_title,name=name,about_me=about_me,num=num,email=email,image=path))
        db.session.commit()
        return redirect('/add-about-me/')
    

@app.route('/add-post/', methods=['GET','POST'])
@login_required
def add_post():
    try:
        if request.method == 'POST':
            category = request.form['category']
            blog_meta_description = request.form['blog_meta_description']
            blog_meta_keywords = request.form['blog_meta_keywords']
            blog_title = request.form['blog_title']
            editor1 = request.form['editor1']
            image = request.files['img']
            filename = secure_filename(image.filename)
            path = '/static/uploads/blog/'+filename
            image.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
            entry = Posts(category=category,blog_meta_description=blog_meta_description, blog_meta_keywords=blog_meta_keywords, blog_title = blog_title, textarea = editor1, image=path )
            db.session.add(entry)
            db.session.commit()
            db.session.close()
            return redirect('/add-post/')
        else:
            category = Category.query.all()
            return render_template('post/add_post.html',category=category)
    except IntegrityError:
        db.session.rollback()
        flash('Title is alredy exist in database')
        return redirect('/add-post/')
            

@app.route('/delete-post/<int:id>/', methods=['GET','POST'])
@login_required
def delete_post(id):
    delete_post = Posts.query.filter_by(id=id).delete()
    db.session.commit()
    db.session.close()
    return redirect('/view-blogs/')

@app.route('/remove-post/<int:id>/', methods=['GET','POST'])
@login_required
def remove_post(id):
    u = Posts.query.filter_by(id=id).update(dict(status=True))
    db.session.commit()
    db.session.close()
    return redirect('/view-blogs/')

@app.route('/update-post/<id>/', methods=['GET','POST'])
@login_required
def update_post(id):
    if request.method == 'POST':
        blog_meta_description = request.form['blog_meta_description']
        blog_meta_keywords = request.form['blog_meta_keywords']
        blog_title = request.form['blog_title']
        editor1 = request.form['editor1']
        image = request.files['img']
        filename = secure_filename(image.filename)
        path = '/static/uploads/blog/'+filename
        image.save(os.path.join(app.config['UPLOAD_FOLDER'],filename))
        exist = Posts.query.filter_by(blog_title=request.form['blog_title']).first()
        if exist:
            return "Tile is alredy exist in database"
        else:
            u = Posts.query.filter_by(id=id).update(dict(blog_meta_description=blog_meta_description, blog_meta_keywords=blog_meta_keywords, blog_title = blog_title, textarea = editor1, image=path))
            db.session.commit()
            db.session.close()
            return redirect('/view-blogs/')
    else:
        data = Posts.query.filter_by(id=id)
        category = Category.query.all()
        return render_template('post/update_posts.html',data=data,category=category)

# #######************************Contact************************
@app.route('/contact/', methods=['GET','POST'])
def contact():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        subject = request.form['subject']
        message = request.form['message']
        if len(name)>500 or len(email)>500 or len(subject)>500 or len(message)>500:
            error = "Please enter less than 500 charaters"
            about = About.query.filter_by(status=False)
            return render_template('contact/contact.html',error=error,about=about)
        else:
            entry = Contact(Name=name,Email=email,Subject=subject,Message=message)
            db.session.add(entry)
            db.session.commit()
            db.session.close()
            done = "Your message hase been sent Successfully"
            return render_template('contact/contact.html',done=done)
    else:
        pro = About.query.filter_by(status='False').all()
    return render_template('contact/contact.html',pro=pro)

@login_required
def view_contact(id):
    contact = Contact.query.filter_by(status=False,id=id)
    return render_template('contact/view_contact.html',contact=contact)

@login_required
def remove_contact(id):
    contact = Contact.query.filter_by(id=id).update(dict(status=True))
    db.session.commit()
    db.session.close()
    return redirect('/all-contacts/')

@login_required
def delete_contact(id):
    contact = Contact.query.filter_by(id=id).delete()
    db.session.commit()
    db.session.close()
    return redirect('/all-contacts/')

@login_required
@app.route('/all-contacts/', methods=['GET','POST'])
def all_contacts():
    contact = Contact.query.filter_by(status=False)
    return render_template('contact/all_contact.html',contact=contact)

####**********************End Contact*************************

####**********************Category*************************
@login_required
@app.route('/category/', methods=['GET','POST'])
def category():
    if request.method=='POST':
        category = request.form['category']
        entry = Category(category=category)
        db.session.add(entry)
        db.session.commit()
        db.session.close()
        return redirect('/category/')
    else:
        category = Category.query.all()
    return render_template('category/add_category.html',category=category)

@login_required
def delete_category(id):
    category = Category.query.filter_by(id=id).delete()
    db.session.commit()
    db.session.close()
    return redirect('/category/')
####**********************End Category*************************

####**********************mindex*************************
@login_required
@app.route('/mindex/', methods=['GET','POST'])
def mindex():
    if request.method=='POST':
        index_meta_description = request.form['index_meta_description']
        index_meta_keywords = request.form['index_meta_keywords']
        index_title = request.form['index_title']
        entry = Index(index_meta_description=index_meta_description,index_meta_keywords=index_meta_keywords,index_title=index_title)
        db.session.add(entry)
        db.session.commit()
        db.session.close()
        return redirect("/mindex/")
    else:
        meta = Index.query.all()
    return render_template('home/add_index_meta.html',meta=meta)

@login_required
@app.route('/update-imeta/<id>/', methods=['GET','POST'])
def update_imeta(id):
    if request.method=='POST':
        index_meta_description = request.form['index_meta_description']
        index_meta_keywords = request.form['index_meta_keywords']
        index_title = request.form['index_title']
        data = Index.query.filter_by(id=id).update(dict(index_meta_description=index_meta_description,index_meta_keywords=index_meta_keywords,index_title=index_title))
        db.session.commit()
        db.session.close()
        return redirect("/mindex/")

####**********************End mindex*************************


# ###############ABOUT ME PAGE #############################
@app.route('/aboutme/')
def aboutme():
    about = About.query.all()
    pro = About.query.filter_by(status='False').all()
    return render_template('about/aboutme.html',about=about,pro=pro)

# ###############END ABOUT ME PAGE #############################

# ############### Trash #############################
@login_required
@app.route('/deleted-contacts/')
def deleted_contacts():
    contacts = Contact.query.filter_by(status=True)
    return render_template('contact/deleted_contacts.html',contacts=contacts)

def restore_contact(id):
    contact = Contact.query.filter_by(id=id).update(dict(status=False))
    db.session.commit()
    db.session.close()
    return redirect("/deleted-contacts/")

@login_required
@app.route('/deleted-posts/')
def deleted_posts():
    posts = Posts.query.filter_by(status=True)
    return render_template('post/deleted_posts.html',posts=posts)

def restore_posts(id):
    posts = Posts.query.filter_by(id=id).update(dict(status=False))
    db.session.commit()
    db.session.close()
    return redirect("/deleted-posts/")

@app.errorhandler(404)
def not_found(e): 
    return render_template("backend_dashboard/404.html")

# ###############END Trash #############################



#################End##Dashboard###########################

##-------index---add-url------------##

app.add_url_rule("/","index",index)
app.add_url_rule("/add-about-me/","add_about",add_about)
app.add_url_rule("/update-post/<id>/","update_post",update_post)
app.add_url_rule("/update-about-me/<int:id>/","update_about_me",update_about_me)
app.add_url_rule("/blog-detail/<slug>/","post_detail",post_detail)
app.add_url_rule("/contact/","contact",contact)
##---------------add-url------------##



##--------dashboard---add-url--------##
app.add_url_rule("/add-post/","add_post",add_post)
app.add_url_rule("/admin-login/","login",login)
app.add_url_rule("/delete-post/<int:id>/","delete_post",delete_post)
app.add_url_rule("/remove-post/<int:id>/","remove_post",remove_post)
app.add_url_rule("/view-blogs/","view_blogs",view_blogs)
app.add_url_rule("/adminurl-login/","backend_dashboard",backend_dashboard)
app.add_url_rule("/view-contact/<int:id>/","view_contact",view_contact)
app.add_url_rule("/remove-contact/<int:id>/","remove_contact",remove_contact)
app.add_url_rule("/delete-contact/<int:id>/","delete_contact",delete_contact)
app.add_url_rule("/delete-category/<int:id>/","delete_category",delete_category)
app.add_url_rule("/restore-contact/<int:id>/","restore_contact",restore_contact)
app.add_url_rule("/restore-posts/<int:id>/","restore_posts",restore_posts)
app.add_url_rule("/aboutme/","aboutme",aboutme)

##------dashboard--add-url------------##


if __name__ == '__main__':

    app.run(debug=False)


     
