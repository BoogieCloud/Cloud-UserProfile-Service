# Import functions and objects the microservice needs.
# - Flask is the top-level application. You implement the application by adding methods to it.
# - Response enables creating well-formed HTTP/REST responses.
# - requests enables accessing the elements of an incoming HTTP/REST request.
#
import jwt
from flask import Flask, Response, request, session, g, render_template, url_for, redirect, make_response

from datetime import datetime, timedelta
import json

from DataAccess import ETag
from Middleware import notification
# from scripts import forms
from Context.Context import Context
import DataAccess.ETag

from Services.CustomerInfo.Users import UsersService as UserService
from Services.CustomerInfo.Users import ProfileService as ProfileService
from Services.RegisterLogin.Registerlogin import RegisterLoginSvc as RegisterLoginSvc
from Services.AddressValidation.ValidatorService import ValidatorService
import Middleware.security as security_middleware

from uuid import uuid4

# Setup and use the simple, common Python logging framework. Send log messages to the console.
# The application should get the log level out of the context. We will change later.
#
import logging

from DataAccess.DataObject import UsersRDB

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)


###################################################################################################################

# EB looks for an 'application' callable by default.
# This is the top-level application that receives and routes requests.
application = Flask(__name__)
application.secret_key = "OCML3BRawWEUeaxcuKHLpw"

# add a rule for the index page. (Put here by AWS in the sample)
# application.add_url_rule('/', 'index', (lambda: base()))
@application.route('/')
def base():
    return render_template('index.html')
##################################################################################################################
# The stuff I added begins here.


_default_context = None
_user_service = None
_registration_service = None
v_service = None


def _get_default_context():
    global _default_context

    if _default_context is None:
        _default_context = Context.get_default_context()

    return _default_context


def _get_user_service():
    global _user_service

    if _user_service is None:
        _user_service = UserService(_get_default_context())

    return _user_service


def _get_registration_service():
    global _registration_service

    if _registration_service is None:
        _registration_service = RegisterLoginSvc()

    return _registration_service


def init():
    global _default_context, _user_service, _registration_service, v_service

    _default_context = Context.get_default_context()
    _user_service = UserService(_default_context)
    _registration_service = _get_registration_service()
    v_service = ValidatorService(_default_context)

    logger.debug("_user_service = " + str(_user_service))


def handle_args(args):
    """

    :param args: The dictionary form of request.args.
    :return: The values removed from lists if they are in a list. This is flask weirdness.
        Sometimes x=y gets represented as {'x': ['y']} and this converts to {'x': 'y'}
    """

    result = {}

    if args is not None:
        for k, v in args.items():
            if type(v) == list:
                v = v[0]
            result[k] = v

    return result


# 1. Extract the input information from the requests object.
# 2. Log the information
# 3. Return extracted information.
def log_and_extract_input(method, path_params=None):
    path = request.path
    args = dict(request.args)
    data = None
    headers = dict(request.headers)
    method = request.method
    url = request.url
    base_url = request.base_url

    try:
        if request.data is not None:
            data = request.json
        else:
            data = None
    except Exception as e:
        # This would fail the request in a more real solution.
        data = "You sent something but I could not get JSON out of it."

    log_message = str(datetime.now()) + ": Method " + method

    # Get rid of the weird way that Flask sometimes handles query parameters.
    args = handle_args(args)

    inputs = {
        "path": path,
        "method": method,
        "path_params": path_params,
        "query_params": args,
        "headers": headers,
        "body": data,
        "url": url,
        "base_url": base_url
    }

    log_message += " received: \n" + json.dumps(inputs, indent=2)
    logger.debug(log_message)

    return inputs


def log_response(method, status, data, txt):
    msg = {
        "method": method,
        "status": status,
        "txt": txt,
        "data": data
    }

    logger.debug(str(datetime.now()) + ": \n" + json.dumps(msg, indent=2))


# returns None if the action is authorized, else return anything
@application.before_request
def check_security():
    # print("check security here")
    if request.method == "OPTIONS":  # allow CORS requests
        return Response("", status=204, headers={"Connection": "keep-alive",
                                                 "Access-Control-Allow-Origin": '*',
                                                 "Access-Control-Allow-Methods": "POST, GET, PUT, DELETE",
                                                 "Access-Control-Max-Age": "86400",
                                                 "Access-Control-Allow-Headers": '*'})
    token = request.headers.get("Login-Token", None)
    return security_middleware.authorize(request, token)


# handles http credentials
# @application.after_request
# def add_header(response: Response):
#     response.headers.add("Access-Control-Allow-Credentials", "true")
#     response.headers.add("Access-Control-Allow-Origin", str(request.url_root))  # TODO: change to production
#     response.headers.add("Access-Control-Allow-Methods", "GET,PUT,POST,DELETE,UPDATE,OPTIONS")
#     response.headers.add("Access-Control-Allow-Headers", "X-Requested-With, X-HTTP-Method-Override, Content-Type, Accept")
#
#     return response

# The only method is POST
# The method takes a body with last name, first name, email and password. Do not worry about password security now.
# Other columns:
# auto_id is an auto-increment column.
# id is a string representation of a GUID. You can generate using a Python package.
# status always starts out as PENDING. You will see why later.
# The method and code create a new user in the users table.


@application.route("/api/registrations", methods=["POST"])
def register():
    last_name = request.args.get("last_name")
    first_name = request.args.get("first_name")
    email = request.args.get("email")
    password = request.args.get("password")

    valid = all([last_name, first_name, email, password])

    user_info = {"last_name": last_name,
                 "first_name": first_name,
                 "email": email,
                 "password": password,
                 "id": str(uuid4()),
                 "status": "PENDING"}

    inputs = log_and_extract_input(register, {"last_name": last_name, "first_name": first_name,
                                              "email": email, "password": password})

    # http://127.0.0.1:5000/api/registrations?last_name=asd&first_name=dsa&email=fdsafdsgf&password=1123
    # If invalid argument
    if not valid:
        rsp = Response("Some columns are empty. last_name, first_name, email, password are required",
                       status=200, content_type="test/plain")
        return rsp

    user_data = UsersRDB.get_by_email(user_info["email"], include_deleted=True)
    if user_data:
        if user_data.get("status", None) != "PENDING":
            rsp = Response("User already exist", status=400, content_type="test/plain")
            return rsp
        else:
            notification.publish_it(email)
            rsp = Response("User " + user_data.get("id", "") + " already exist, resent activation email.",
                           status=200, content_type="test/plain")
            return rsp

    try:
        # result = UsersRDB.create_user(user_info)
        result = UserService.create_user(user_info)
        rsp = Response("User created, user ID is:" + (result if result else "") + " please verify your email",
                       status=200, content_type="test/plain")
    except Exception as e:
        rsp = Response("Invalid argument", status=400, content_type="test/plain")
        logger.debug(str(e))
    return rsp


@application.route("/api/user", methods=["PUT", "DELETE", "GET"], provide_automatic_options=True)
def user():
    last_name = request.args.get("last_name")
    first_name = request.args.get("first_name")
    email = request.args.get("email")
    password = request.args.get("password")
    status = request.args.get("status")

    inputs = log_and_extract_input(demo, {"last_name": last_name,
                                          "first_name": first_name,
                                          "email": email,
                                          "password": password,
                                          "status": status})

    user_info = inputs["path_params"]

    try:
        user_data = UsersRDB.get_by_email(user_info["email"], include_deleted=False)
        if not user_data:
            return Response("No such user found", status=400, content_type="text/plain")

        if inputs["method"] == "GET":
            etag_server = ETag.getMD5(user_data)
            rsp_txt = json.dumps(user_data)
            full_rsp = Response(rsp_txt, status=200, content_type="application/json",
                                headers={"ETag": etag_server})

        elif inputs["method"] == "PUT":
            # check etag before updating anything
            etag_client = request.headers.get("ETag", None)
            etag_server = ETag.getMD5(user_data)
            if etag_client is None:
                Response("No ETag provided, please sign in first", status=403, content_type="text/plain")
            if etag_client != etag_server:
                return Response("ETag mismatch, please pull the latest data", status=412, content_type="text/plain")

            # update the data
            temp_data = {}
            for k, v in user_data.items():
                # if the value for certain columns are not specified (None) or empty (""), keep the original data
                if user_info.get(k, "") not in [None, ""]:
                    # update column to new data
                    temp_data[k] = user_info.get(k, "")
                else:
                    # keep original data
                    temp_data[k] = v
            # don't allow set to delete in PUT method
            if temp_data.get("status") == "DELETED":
                return Response("Please use DELETE method instead", status=403, content_type="text/plain")
            res = UsersRDB.update(temp_data)
            if res == 0:
                rsp_txt = "Nothing updated"
            else:
                rsp_txt = "User successfully updated"
            full_rsp = Response(rsp_txt, status=200, content_type="text/plain")

        elif inputs["method"] == "DELETE":
            temp_data = {}
            for k, v in user_data.items():
                if user_info.get(k, None):
                    temp_data[k] = user_info.get(k, None)
                else:
                    temp_data[k] = v
            temp_data["status"] = "DELETED"
            res = UsersRDB.update(temp_data)
            rsp_txt = "User successfully set to deleted state"
            full_rsp = Response(rsp_txt, status=200, content_type="text/plain")

    except Exception as e:
        log_msg = "/user: Exception = " + str(e)
        logger.error(log_msg)
        rsp_status = 500
        rsp_txt = "INTERNAL SERVER ERROR. Please take COMSE6156 -- Cloud Native Applications."
        full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")

    return full_rsp


@application.route("/resource", methods=["GET"])
def get_resource_by_columns():
    args = dict(request.args)
    args = handle_args(args)

    fields = request.args.get("f")
    if fields:
        fields = fields.split(",")
        args.pop("f")
    else:
        fields = None

    try:
        res = UsersRDB.get_by_columns(args, fields=fields)
        rsp_txt = json.dumps(res)
        full_rsp = Response(rsp_txt, status=200, content_type="json/application")

    except Exception as e:
        log_msg = "/user: Exception = " + str(e)
        logger.error(log_msg)
        rsp_status = 500
        rsp_txt = "INTERNAL SERVER ERROR when running get_resource"
        full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")

    return full_rsp


@application.route("/resource/<primary_key>", methods=["GET"])
def get_resource_by_primary_key(primary_key):
    fields = request.args.get("f")
    if fields:
        fields = fields.split(",")
    else:
        fields = None

    if not primary_key:
        return Response("Please provide primary key", status=400, content_type="text/plain")
    try:
        user_data = UsersRDB.get_by_id(primary_key, fields)
        rsp_txt = json.dumps(user_data)
        full_rsp = Response(rsp_txt, status=200, content_type="json/application")

    except Exception as e:
        log_msg = "/user: Exception = " + str(e)
        logger.error(log_msg)
        rsp_status = 500
        rsp_txt = "INTERNAL SERVER ERROR when running get_resource"
        full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")

    return full_rsp


@application.route("/api/login", methods=["POST"])
def login():
    email = request.args.get("email")
    password = request.args.get("password")

    valid = all([email, password])
    if not valid:
        return Response("Invalid Argument", status=400, content_type="text/plain")

    try:
        user_data = UsersRDB.get_by_email(email, include_deleted=False)
        if not user_data:
            return Response("No such user found", status=400, content_type="text/plain")

        if user_data.get("password", None) != password:
            return Response("Incorrect password", status=400, content_type="text/plain")

        token = security_middleware.generate_token(user_data)

        header = {"Login-Token": token}
        full_rsp = Response(json.dumps(user_data),
                            status=200, content_type="json/application", headers=header)
        # full_rsp = Response("Login Successful: " + user_data.get("first_name", "user") + " " +
        #                     user_data.get("last_name", "user") + "\nSTATUS: " + user_data.get("status", "PENDING"),
        #                     status=200, content_type="text/plain", headers=header)


    except Exception as e:
        logger.error("Login error: " + str(e))
        rsp_txt = "INTERNAL SERVER ERROR when running login"
        full_rsp = Response(rsp_txt, status=500, content_type="text/plain")

    return full_rsp


# helper route for communicating with lambda function
@application.route("/api/activate/<email>", methods=["PUT"])
def activate(email):
    token = request.headers.get("Lambda-Token")
    if token != security_middleware._secret:
        # logger.debug("Invalid token: " + str(token) + " VS " + str(security_middleware._secret))
        # logger.debug("Header received:\n" + str(request.headers))
        return Response("Invalid Authorization Token", status=401, content_type="text/plain")

    try:
        user_data = UsersRDB.get_by_email(email, include_deleted=False)
        if not user_data:
            return Response("No such user found", status=400, content_type="text/plain")
        if user_data["status"] == "ACTIVE":
            return Response("User already activated", status=200, content_type="text/plain")

        user_data["status"] = "ACTIVE"
        UsersRDB.update(user_data)
        full_rsp = Response("User successfully activated", status=200, content_type="text/plain")

    except Exception as e:
        log_msg = "/activate: Exception = " + str(e)
        logger.error(log_msg)
        rsp_status = 500
        rsp_txt = "/activate INTERNAL SERVER ERROR."
        full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")

    return full_rsp

'''
@application.route("/api/address", methods=["POST"])
def post_address():
    address = dict(request.args)
    address = handle_args(address)
    try:
        logger.debug(str(address))
        v_service = ValidatorService(_get_default_context())
        t_answer = v_service.validate_address(address)
        if t_answer is not None:
            return Response(json.dumps(t_answer), status=200, content_type="application/json")
    except Exception as e:
        return Response(str(e),status=500, content_type="text/plain")


@application.route('/api/address/address_id', methods=["GET"])
def get_address_id():
    address = dict(request.args)
    address = handle_args(address)
    id = address['address_id']

    try:
        v_service = ValidatorService(_get_default_context())
        t_answer = v_service.get_from_addressid(id)
        if t_answer is not None:
            return Response(json.dumps(t_answer), status=200, content_type="application/json")
        else:
            return Response('Invalid address_id', status=500, content_type="text/plain")

    except Exception as e:
        return Response(str(e), status=500, content_type="text/plain")

'''


@application.route('/api/profile', methods=['GET', 'POST'])
def user_profile():
    profile = dict(request.args)
    if request.method == 'GET':
        try:
            result = ProfileService.get_profile(profile)
            if result is not None:
                return Response(json.dumps(result), status=200, content_type="application/json")
            else:
                return Response('Invalid request', status=500, content_type="text/plain")
        except Exception as e:
            return Response(str(e), status=500, content_type="text/plain")
    if request.method == 'POST':
        try:
            result = ProfileService.create_profile(profile)
            if result is not None:
                return Response('Create profile with customer_id = '+ str(result), status=200, content_type="application/json")
        except Exception as e:
            return Response(str(e), status=500, content_type="text/plain")


@application.route('/api/customers/customer_id/profile', methods=['GET', 'PUT', 'DELETE'])
def profile_customer_id():
    profile = dict(request.args)
    customer_id = profile['customer_id']
    if request.method == 'GET':
        try:
            result = ProfileService.get_from_id(customer_id)
            if result is not None:
                return Response(json.dumps(result), status=200, content_type="application/json")
            else:
                return Response('Invalid customer_id', status=500, content_type="text/plain")
        except Exception as e:
            return Response(str(e), status=500, content_type="text/plain")
    if request.method == 'PUT':
        try:
            result = ProfileService.update_from_id(customer_id, profile)
            if result != 0:
                return Response("Updated with customer_id = "+ customer_id, status=200, content_type="application/json")
            else:
                return Response('Invalid profile information', status=500, content_type="text/plain")
        except Exception as e:
            return Response(str(e), status=500, content_type="text/plain")
    if request.method == 'DELETE':
        try:
            result = ProfileService.delete_from_id(profile)
            if result != 0:
                return Response("Deleted with customer_id = "+ customer_id, status=200, content_type="application/json")
            else:
                return Response('Invalid customer_id', status=500, content_type="text/plain")
        except Exception as e:
            return Response(str(e), status=500, content_type="text/plain")





# @application.route("/api/registration", methods=["POST", "GET"])
# def registration():
#
#     form = forms.LoginForm(request.form)
#     user_info = {}
#     if request.method == 'POST':
#         user_info['first_name'] = request.form['firstname']
#         user_info['last_name'] = request.form['lastname']
#         user_info['password'] = request.form['password']
#         user_info['email'] = request.form['email']
#         user_info["id"] = str(uuid4())
#         user_info["status"] = "PENDING"
#
#         _, tok = RegisterLoginSvc.register(user_info)
#         session.clear()
#         session["Authorization"] = tok
#         headers = {"Authorization": tok}
#         print(url_for('login'))
#         return json.dumps({'status': 'Signup successful'})
#         response = redirect(url_for('login'))
#         response.headers = headers
#         return response
#     return render_template('login.html', form=form)
#
#     inputs = log_and_extract_input(demo, {"parameters": None})
#     rsp_data = None
#     rsp_status = None
#     rsp_txt = None
#
#     try:
#
#         r_svc = _get_registration_service()
#
#         logger.error("/api/registration: _r_svc = " + str(r_svc))
#
#         if inputs["method"] == "POST":
#
#             rsp = r_svc.register(inputs['body'])
#
#             if rsp is not None:
#                 rsp_data = rsp
#                 rsp_status = 201
#                 rsp_txt = "CREATED"
#                 link = rsp_data[0]
#                 auth = rsp_data[1]
#             else:
#                 rsp_data = None
#                 rsp_status = 404
#                 rsp_txt = "NOT FOUND"
#         else:
#             rsp_data = None
#             rsp_status = 501
#             rsp_txt = "NOT IMPLEMENTED"
#
#         if rsp_data is not None:
#             # TODO Generalize generating links
#             headers = {"Location": "/api/users/" + link}
#             headers["Authorization"] = auth
#             full_rsp = Response(rsp_txt, headers=headers,
#                                 status=rsp_status, content_type="text/plain")
#         else:
#             full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")
#
#     except Exception as e:
#         log_msg = "/api/registration: Exception = " + str(e)
#         logger.error(log_msg)
#         rsp_status = 500
#         rsp_txt = "INTERNAL SERVER ERROR. Please take COMSE6156 -- Cloud Native Applications."
#         full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")
#
#     log_response("/api/registration", rsp_status, rsp_data, rsp_txt)
#
#     return full_rsp


# @application.route("/api/login", methods=["POST", "GET"])
# def login():
#     form = forms.LoginForm(request.form)
#     inputs = log_and_extract_input(login, {"parameters": None})
#     rsp_data = dict()
#     rsp_status = None
#     rsp_txt = None
#
#     try:
#
#         r_svc = _get_registration_service()
#
#         logger.error("/api/login: _r_svc = " + str(r_svc))
#
#         if inputs["method"] == "POST":
#
#             rsp = r_svc.login(inputs['body'])
#
#             if rsp is not None:
#                 rsp_data['status'] = "OK"
#                 rsp_data['Authorization'] = rsp
#                 rsp_status = 201
#                 rsp_txt = "CREATED"
#             else:
#                 rsp_data = None
#                 rsp_status = 403
#                 rsp_txt = "NOT AUTHORIZED"
#         else:
#             rsp_data = None
#             rsp_status = 501
#             return render_template('login.html')
#
#         if rsp_data is not None:
#             # TODO Generalize generating links
#             session.clear()
#             session["Authorization"] = rsp
#             headers = {"Authorization": rsp}
#             full_rsp = Response(json.dumps(rsp_data, default=str), headers=headers,
#                                 status=rsp_status, content_type="application/json")
#         else:
#             full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")
#
#     except Exception as e:
#         log_msg = "/api/registration: Exception = " + str(e)
#         logger.error(log_msg)
#         rsp_status = 500
#         rsp_txt = "INTERNAL SERVER ERROR. Please take COMSE6156 -- Cloud Native Applications."
#         full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")
#
#     log_response("/api/login", rsp_status, rsp_data, rsp_txt)
#
#     return full_rsp


# This function performs a basic health check. We will flesh this out.
@application.route("/health", methods=["GET"])
def health_check():
    rsp_data = {"status": "healthy", "time": str(datetime.now())}
    rsp_str = json.dumps(rsp_data)
    rsp = Response(rsp_str, status=200, content_type="application/json")
    return rsp


@application.route("/demo/<parameter>", methods=["GET", "POST"])
def demo(parameter):
    inputs = log_and_extract_input(demo, {"parameter": parameter})

    msg = {
        "/demo received the following inputs": inputs
    }

    rsp = Response(json.dumps(msg), status=200, content_type="application/json")
    return rsp


@application.route("/api/user/<email>", methods=["GET", "PUT", "DELETE"])
# email will be directly passed to the function below
def user_email(email):
    global _user_service

    inputs = log_and_extract_input(demo, {"parameters": email})
    rsp_data = None
    rsp_status = None
    rsp_txt = None

    try:

        user_service = _get_user_service()

        logger.error("/email: _user_service = " + str(user_service))

        if inputs["method"] == "GET":

            rsp = user_service.get_by_email(email)

            if rsp is not None:
                rsp_data = rsp
                rsp_status = 200
                rsp_txt = "OK"
            else:
                rsp_data = None
                rsp_status = 404
                rsp_txt = "NOT FOUND"
        else:
            rsp_data = None
            rsp_status = 501
            rsp_txt = "NOT IMPLEMENTED"

        if rsp_data is not None:
            full_rsp = Response(json.dumps(rsp_data), status=rsp_status, content_type="application/json")
        else:
            full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")

    except Exception as e:
        log_msg = "/email: Exception = " + str(e)
        logger.error(log_msg)
        rsp_status = 500
        rsp_txt = "INTERNAL SERVER ERROR. Please take COMSE6156 -- Cloud Native Applications."
        full_rsp = Response(rsp_txt, status=rsp_status, content_type="text/plain")

    log_response("/email", rsp_status, rsp_data, rsp_txt)

    return full_rsp


logger.debug("__name__ = " + str(__name__))
# run the app.
if __name__ == "__main__":
    # Setting debug to True enables debug output. This line should be
    # removed before deploying a production app.

    logger.debug("Starting Project EB at time: " + str(datetime.now()))
    init()

    application.debug = True
    application.run()
