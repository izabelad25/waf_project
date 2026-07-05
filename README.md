**Web Application Firewall** _(Bachelor's Thesis Project)_

python based Reverse Proxy Web Application Firewall that runs locally 

```
-> Dashboard for monitoring 
-> Regex Rule filtering
-> Custom rules 
-> Behavioural and Volumetric Log Analysis 
-> Real-time alert via email
-> Automatic archiver (compresses old activity logs) 
-> ML anomaly detection (Isolation Forest) + retraining based on your application web traffic

```

                     ___________
                    ||"+.+"+.+"||            _______
                    || FIREWALL||           | _____ |
                    ||        .||           ||*____||
                    ||__"+.+"+_||           |  ___  |
                    |  + = = +  |           | |___*||
                        _|_|_   \           |       |
                       (_____)   \          |       |
                                  \    ___  |       |
                           ______  \__/   \_|       |
                          |   _  |      _/  |       |
                          |  ( ) |     /    |_______|
                          |___|__|    /         
                               \_____/

**How to use?**
_-- this WAF version works only for web applications that have frontend and backend running on different ports_
1. Start your web application (backend) on any port.
2. Start the WAF --> open the dashboard _(detailed instructions will be shown at start-up too)_.
3. Easy config using the HOME section in the UI (_dashboard_).
4. Make sure that the frontend part of your web app points to the reverse proxy port instead of the backend one.
5. Check **rules**, **live traffic**, **analytics** and **scan for anomalies** while your app works normally ! 



-------------------------------------------------------
! Email alerts can be optional 
-> for activation **create an .env file** and add the following:
```
        MAIL_ALERT=email...@gmail.com
        MAIL_APP_PASS=xxxx xxxx xxxx xxxx
```
        ** MAIL_APP_PASS is a Google App Password (not a regular email login password) !

--------------------------------------------------------

INSTALL >> run the following (clone the project)

1.
```bash
  git clone https://github.com/<user>/waf_project.git
  cd waf_project
  python -m venv venv
```

2. (activate venv)
```bash
    .\venv\Scripts\Activate.ps1 (windows)
    source venv/bin/activate (linux/macOs)
```

3.    
```bash
   pip install -r requirements.txt
   cd server
   python main.py (runs the waf server)
```

OR DOWNLOAD directly (no python interpreter required) 
>>>> check RELEASES --> WAF tag --> DOWNLOAD the binary file and read the instructions ! 



