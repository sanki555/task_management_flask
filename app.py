#from werkzeug.security import generate_password_hash, check_password_hash
import uuid 
import jwt
import datetime
from flask import Flask, request, jsonify, make_response   
import mysql.connector as conn
from werkzeug.security import generate_password_hash, check_password_hash
from apiResponse import apiResponse
from flask_cors import CORS
from functools import wraps
import base64
import rncryptor


db = conn.connect(host = 'db4free.net',
                      user= 'asdfqwrqw',
                      passwd = 'sanket1234',
                      database = 'aasdfgshfgadg1')

cur=db.cursor(dictionary=True)
app = Flask(__name__)
app.config['SECRET_KEY']='Th1s1ss3cr3t' 
CORS(app,supports_credentials=True)



def token_required(f):  
    @wraps(f)  
    def decorator(*args, **kwargs):

       token = None 
       token = request.cookies.get('token') 


       if not token:  
          return jsonify({'data': 'a valid token is missing','statusCode':'504'})   


       try:  
          data = jwt.decode(token, app.config['SECRET_KEY']) 
          current_user = data['public_id']
          user_id = data['user_id']
          return f(user_id, *args,  **kwargs)  
       except Exception as e:
            print(e)  
            return jsonify({'data': 'token is invalid','statusCode':'504'})  

    return decorator

          
@app.route('/')
def index():
    return "<h1>Welcome to our server !!</h1>"     


@app.route('/tasks', methods=['GET'])
@token_required 
def get_all_tasks(user_id):
    print("user_id"+str(user_id))  
    cur.execute("select * from tasks where user_id = %s",(str(user_id),))   
    myresult = cur.fetchall()
    for x in myresult:
        print(x)
    
    print(myresult)
    apiResponse['data'] = myresult
    apiResponse['statusCode'] = 200
    return apiResponse

@app.route('/tasks/<taskId>', methods=['GET'])
@token_required 
def get_task_by_Id(user_id,taskId):  
    print("Task -id "+taskId)
    
    try:
        cur.execute("SELECT * FROM tasks where task_id = %s",(taskId,))   
        myresult = cur.fetchall()
        
        for x in myresult:
            print(x)
        if(len(myresult)==0):
            apiResponse['data'] = "Invalid Task Id"
            apiResponse['statusCode'] = 404
            return apiResponse 
        
        print(myresult)
        apiResponse['data'] = myresult
        apiResponse['statusCode'] = 200
    except Exception as e:
        print(e) 
        apiResponse['data'] = "Problem Occured"
        apiResponse['statusCode'] = 404
    return apiResponse



@app.route('/addTask', methods=['POST'])
@token_required 
def add_tasks(user_id): 
    req_data = request.get_json()
    print(req_data)
    taskName =  req_data['taskName']
    user_id = user_id
    print(taskName)
    cur.execute("insert into tasks (task_name,user_id,status,created_on,modified_on) values ( %s,%s ,'INITIATED',now(),now())",(taskName,str(user_id),))
    
    if cur.rowcount > 0:
        db.commit()
        apiResponse['data'] = "Success"
        apiResponse['statusCode'] = 200
    else:
        db.rollback()
        apiResponse['data'] = "Failed"
        apiResponse['statusCode'] = 300
    return apiResponse

@app.route('/deleteTask/<taskId>', methods=['GET'])
@token_required 
def deleteTask(user_id,taskId):
    print("Task -id "+taskId)
    print("user_id -id "+str(user_id))
    cur.execute("delete from tasks where task_id = %s and user_id = %s",(taskId,str(user_id),))
    if cur.rowcount > 0:
        db.commit()
        apiResponse['data'] = "Success"
        apiResponse['statusCode'] = 200
    else:
        db.rollback()
        apiResponse['data'] = "Failed"
        apiResponse['statusCode'] = 300
    return apiResponse    

@app.route('/register', methods=['POST'])
def signup_user():
    data = request.get_json()
    print("Data "+str(data))
    hashed_password = generate_password_hash(data['password'], method='sha256')
    print(hashed_password)
    username = data['username']
    try:
        cur.execute("insert into user (username,password) values ( %s , %s )",(username,hashed_password,))
    except Exception as e:
        print(e)
        db.rollback()
        apiResponse['data'] = "Problem Occured"
        apiResponse['statusCode'] = 313
        return apiResponse
    if cur.rowcount > 0:
        db.commit()
        apiResponse['data'] = "registered successfully"
        apiResponse['statusCode'] = 200
    else:
        db.rollback()
        apiResponse['data'] = "Failed"
        apiResponse['statusCode'] = 300
    return apiResponse

@app.route('/login', methods=['POST'])
def login():
    cryptor = rncryptor.RNCryptor()
    data = request.get_json()
    username = data['username']
    cur.execute("select * from user where username = %s",(username,))
    myresult = cur.fetchall()
    print(myresult)
    db_data= myresult[0]
    print(data['password'])
    password = data['password']
    
    #decrypted_data = base64.b64decode(password)
    #decrypted_data = message_bytes.decode('ascii')
    #decrypted_data = base64.decodestring(data['password']) 
    #print(str(decrypted_data))
    if check_password_hash(db_data['password'],password):
        apiResponse['data'] = "login successfully"
        apiResponse['statusCode'] = 200
        response = make_response(apiResponse)
        token = jwt.encode({'public_id': username,'user_id':db_data['user_id'] ,'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])
        response.set_cookie('token', token,max_age=90 * 60 * 60 * 24)
        return response
    else:
        apiResponse['data'] = "Failed"
        apiResponse['statusCode'] = 300
    return apiResponse     

@app.route('/updateTask', methods=['POST'])
@token_required 
def updateTask(user_id):
    print("user_id"+str(user_id))
    status = None
    task_name = None
    task_id = None
    data = request.get_json()
    if 'status' in data.keys():
        status = data['status']
    if 'taskName' in data.keys():
        task_name = data['taskName']
    if 'task_id' in data.keys():
        task_id = data['task_id']
    else:
        apiResponse['data'] = "task_id is Mandatory"
        apiResponse['statusCode'] = 312
        return apiResponse
    print("task_id"+str(task_id))
    try:
        if status != None and task_name != None:
            cur.execute("update tasks set status = %s , task_name = %s where task_id = %s and user_id = %s",(str(status),task_name,task_id,user_id,))
        elif status != None:
            cur.execute("update tasks set status = %s where task_id = %s and user_id = %s",(str(status),task_id,user_id,))
        elif task_name != None:
            cur.execute("update tasks set status = %s where task_id = %s and user_id = %s",(task_name,task_id,user_id,))
    except:
            db.rollback()
            apiResponse['data'] = "Problem Occured"
            apiResponse['statusCode'] = 300
            return apiResponse 
       
    if cur.rowcount > 0:
        db.commit()
        apiResponse['data'] = "success"
        apiResponse['statusCode'] = 200
        return apiResponse
    else:
        db.rollback()
        apiResponse['data'] = "failed"
        apiResponse['statusCode'] = 300
        return apiResponse


# @app.route('/logout', methods=['GET'])
# def logout():
#     apiResponse['data'] = "login successfully"
#     apiResponse['statusCode'] = 200
#     return apiResponse 


if  __name__ == '__main__':  
     app.run(debug=True) 
