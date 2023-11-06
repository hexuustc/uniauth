from flask import Flask, request, render_template, redirect, flash, url_for
from flask_cors import CORS

import logging
from logging.handlers import RotatingFileHandler

import uuid
import json
import secrets
import re
import urllib
import requests


app = Flask(__name__)
CORS(app)
app.secret_key = 'fpgaol_uniauth_key'

log_file_path = "/home/fpgaol2/uniauth/log/uniauth.log"
#logging.basicConfig(
#    format='%(asctime)s line:%(lineno)s,  %(message)s', level=logging.INFO)

# 设置日志的格式
log_format = logging.Formatter('%(asctime)s line:%(lineno)s,  %(message)s')

# 创建一个日志处理器，用于写入日志文件
file_handler = RotatingFileHandler(log_file_path, maxBytes=10*1024*1024, backupCount=30)
file_handler.setFormatter(log_format)

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
# 模拟数据库
  # users[username] = {"password": password, "user_id": user_id}
ID_FILE = 'current_id.txt'
# 修改 tickets 结构
# tickets[ticket] = {"username": "JohnDoe", "ssoLogoutCall": "..."}
tickets = {}

SERVICE = "https://fpgaol.ustc.edu.cn/uniauth/admin/caslogin"


def save_users_to_file():
    with open('users.json', 'w') as file:
        json.dump(users, file)

def load_users_from_file():
    try:
        with open('users.json', 'r') as file:
            return json.load(file)
    except FileNotFoundError:
        return {}
    
def load_current_id():
    try:
        with open(ID_FILE, 'r') as file:
            return int(file.read().strip())
    except (FileNotFoundError, ValueError):
        return 0

def save_current_id():
    with open(ID_FILE, 'w') as file:
        file.write(str(current_id))

def generate_next_id():
    global current_id
    current_id += 1
    save_current_id()
    return current_id

def register_login(student_id):
    if student_id in users:
        return student_id
    else:
        users[student_id] = {"password": "fpgaol_pw", "user_id": student_id,"ssoLogoutCall":None,"ticket":""}
        save_users_to_file()
        return student_id
        

@app.route('/', methods=['GET'])
def index():
    logger.info("/ in get")
    return redirect('/admin/login')

@app.route('/admin/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        logger.info("login: %s",request.form)
        username = request.form['username']
        password = request.form['password']
        redirect_url = request.form['redirect']
        #logger.debug("getuser: %s, %s",users.get(username),users[username]['password'])
        if users.get(username) and users[username]['password'] == password:
            logger.info("login success")
            # 生成一个随机的 ticket
            ticket = secrets.token_urlsafe(16)
            logger.info("ticket: %s",ticket)
            tickets[ticket] = {"username": username, "ssoLogoutCall": None}
            users[username]['ticket']=ticket
            save_users_to_file()
            # 将 ticket 附加到重定向 URL
            redirect_url_with_ticket = f"{redirect_url}?ticket={ticket}"
            return redirect(redirect_url_with_ticket)
        else:
            logger.info("login failed")
            return "Invalid credentials!", 401
    else:
        logger.info("login in get")
        redirect_url = request.args.get('redirect')
        logger.info("Redirect URL: %s", redirect_url)
        return render_template('login.html', redirect=redirect_url)

@app.route('/admin/caslogin', methods=['GET'])
def caslogin():
    logger.info("caslogin in get")
    ustc_ticket = request.args.get('ticket')
    redirect_url = request.args.get('redirect')
    redirect_url_with_redirect = f"/admin/login?redirect={redirect_url}"
    logger.info(ustc_ticket)
    if len(ustc_ticket) != 35:
        print('1')
        return redirect('/admin/login', redirect=redirect_url_with_redirect)
    pattern = re.compile(r'^ST-\w{32}$')
    if pattern.match(ustc_ticket) is None:
        print('2')
        return redirect('/admin/login', redirect=redirect_url_with_redirect)
    # use ticket
    info = None
    API_URL = "https://passport.ustc.edu.cn/serviceValidate?ticket={ticket}&service={service}?redirect={redirect_url}"
    #API_URL = "https://passport.ustc.edu.cn/serviceValidate?ticket={ticket}&service={service}"
    service_url = urllib.parse.quote_plus(SERVICE)
    api_url = API_URL.format(ticket=ustc_ticket, service=service_url,redirect_url=redirect_url)
    #api_url = API_URL.format(ticket=ustc_ticket, service=service_url)
    logger.info(api_url)
    #exit()
    try:
        r = requests.get(api_url)
        info = r.text
    except Exception as e:
        logger.info(e)
        print('2 {}'.format(e))
        return redirect('/admin/login', redirect=redirect_url_with_redirect)

    logger.info(info)
    # format return info
    if info:
        pattern = re.compile(
            r'<cas:user>([A-Z]{2}\d{8}|[A-Z]\d{4})</cas:user>')
        match = pattern.search(info)
        if match:
            logger.info(match)
            student_id = match.group(1).upper()
            user = register_login(student_id)
            #flash("Ustc login successful! You can now login.", "success")
            logger.info("caslogin success")
            # 生成一个随机的 ticket
            ticket = secrets.token_urlsafe(16)
            logger.info("ticket: %s",ticket)
            tickets[ticket] = {"username": user, "ssoLogoutCall": None}
            users[user]['ticket']=ticket
            save_users_to_file()
            # 将 ticket 附加到重定向 URL
            redirect_url_with_ticket = f"{redirect_url}?ticket={ticket}"
            return redirect(redirect_url_with_ticket)
            
        else:
            print('3')
            print(info)
            return redirect('/admin/login', redirect=redirect_url_with_redirect)
    else:
        print('4')
        return redirect('/admin/login', redirect=redirect_url_with_redirect)
    return redirect('/admin/login', redirect=redirect_url_with_redirect)

@app.route('/admin/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        redirect_url = request.form.get('redirect')

        logger.info("register information: %s",request.form)
        # Check if username already exists
        if username in users:
            logger.info("Username already exists")
            return "Username already exists!", 400

        # Check username and password format
        if not (username.isalnum() and password.isalnum()):
            logger.info("Invalid format for username or password")
            return "Invalid format for username or password!", 400

        # Check if password and confirm_password match
        if password != confirm_password:
            logger.info("Passwords do not match")
            return "Passwords do not match!", 400

        # Generate unique user ID and store user details
        #user_id = str(uuid.uuid4())
        user_id = generate_next_id()
        users[username] = {"password": password, "user_id": user_id,"ssoLogoutCall":None,"ticket":""}
        save_users_to_file()

        logger.info("register success")
        flash("Registration successful! You can now login.", "success")
        login_url = url_for('login', redirect=redirect_url)
        return redirect(login_url)
    else:
        logger.info("register in get")
        redirect_url = request.args.get('redirect')
        return render_template('register.html', redirect=redirect_url)

@app.route('/sso/getUserInfo', methods=['GET', 'POST'])
def get_user_info():
    if request.method == 'POST':
        logger.info("get_user_info in post")
        data = request.json
        ticket = data.get('ticket')
        ssoLogoutCall = data.get('ssoLogoutCall')
        logger.debug("ticket: %s",ticket)
        user_data = tickets.get(ticket)
        if user_data:
            # 将 ssoLogoutCall 信息更新到 tickets 字典中
            user_data['ssoLogoutCall'] = ssoLogoutCall
            username = user_data['username']
            users[username]['ssoLogoutCall']=ssoLogoutCall
            save_users_to_file()
            user_id = users[username]['user_id']
            tickets[ticket] = user_data
            logger.debug("tickets list: %s",tickets)
            return_data = {"code":1,"msg":"成功","data":{"userId":user_id,"username":username}}
            logger.info("get info success: %s",return_data)
            return return_data  # 返回与 ticket 对应的用户数据
        else:
            logger.warning("get info failed")
            return {"code":5,"msg":"未登录","data":{"userId":'',"username":''}}

    # 对于 GET 请求
    logger.info("get_user_info in get")
    return {"please use the post method"}

@app.route('/sso/logout', methods=['GET'])
def logout():
    logger.info("logout in get")
    username = request.args.get('username')
    #ssoLogoutCall=users[username]['ssoLogoutCall']
    if users.get(username):   
        ticket=users[username]['ticket']
        tickets.pop(ticket,None)
        users[username]['ticket']=""
        save_users_to_file()
        logger.info("delete ticket: %s",ticket)
        logger.info("Logged out successfully")
        return {"code":1,"msg":"成功","data":None}
        #return "Logged out successfully", 200
    else:
        return {"code":5,"msg":"未登录","data":{"userId":'',"username":''}}
        

if __name__ == '__main__':
    logger.info('Server started')
    users = load_users_from_file()
    current_id = load_current_id()
    app.run(debug=True,host='127.0.0.1',port=9003)
