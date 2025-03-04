import os
from flask import Flask, request, jsonify, abort
from sqlalchemy import exc
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink, db
from .auth.auth import AuthError, requires_auth

app = Flask(__name__)
setup_db(app)
CORS(app)

'''
@TODO uncomment the following line to initialize the datbase
!! NOTE THIS WILL DROP ALL RECORDS AND START YOUR DB FROM SCRATCH
!! NOTE THIS MUST BE UNCOMMENTED ON FIRST RUN
!! Running this funciton will add one
'''
db_drop_and_create_all()

# ROUTES
'''
@TODO implement endpoint
    GET /drinks
        it should be a public endpoint
        it should contain only the drink.short() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks', methods = ['GET'])
def getDrinks():
    try:
        page = request.args.get('page', 1, type=int)
        start = (page - 1) * 10
        end = start + 10
        drinks = Drink.query.all()
        if start > len(drinks):
            abort(404)
        formatted_drinks = [drink.short() for drink in drinks]
        return jsonify({
            'sucess': True,
            'drinks': formatted_drinks
            })    
    except:
        db.session.rollback()
        abort(404)
    finally:
        db.session.close()


'''
@TODO implement endpoint
    GET /drinks-detail
        it should require the 'get:drinks-detail' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drinks} where drinks is the list of drinks
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks-detail')
@requires_auth('get:drinks-detail')
def getDrinksDetails(jwt):
    try:
        page = request.args.get('page', 1, type=int)
        start = (page - 1) * 10
        end = start + 10
        drinks = Drink.query.all()
        if start > len(drinks):
            abort(404)
        formatted_drinks = [drink.long() for drink in drinks]
        return jsonify({
            'sucess': True,
            'drinks': formatted_drinks
            })
    except:
        db.session.rollback()
        abort(404)
    finally:
        db.session.close()


'''
@TODO implement endpoint
    POST /drinks
        it should create a new row in the drinks table
        it should require the 'post:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the newly created drink
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks', methods = ["POST"])
@requires_auth('post:drinks')
def saveDrinks(jwt):
    try:
        body = request.get_json()
        new_title = body['title']
        new_recipe = json.dumps(body['recipe'])

        print(new_recipe)
        drinks = Drink(
        title=new_title,
        recipe=new_recipe
        )
        drinks.insert()
        drink = [drinks.long()]
        return jsonify({
            "success": True,
            "drinks": drink
        })
    except:
        db.session.rollback()
        abort(404)
    finally:
        db.session.close()


'''
@TODO implement endpoint
    PATCH /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should update the corresponding row for <id>
        it should require the 'patch:drinks' permission
        it should contain the drink.long() data representation
    returns status code 200 and json {"success": True, "drinks": drink} where drink an array containing only the updated drink
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks/<int:id>', methods = ["PATCH"])
@requires_auth('patch:drinks')
def updateDrinks(jwt,id):
    try:
        body = request.get_json()
        drink = Drink.query.filter(Drink.id == id).one_or_none()

        if drink is None:
            abort(404)

        drink.title = body['title']
        drink.recipe = json.dumps(body['recipe'])
        
        updatedrinks = drink.update()
        print(updatedrinks)
        return jsonify({
            "success": True,
            "drinks": [drink.long()]
        }), 200
    except:
        db.session.rollback()
        abort(404)
    finally:
        db.session.close()


'''
@TODO implement endpoint
    DELETE /drinks/<id>
        where <id> is the existing model id
        it should respond with a 404 error if <id> is not found
        it should delete the corresponding row for <id>
        it should require the 'delete:drinks' permission
    returns status code 200 and json {"success": True, "delete": id} where id is the id of the deleted record
        or appropriate status code indicating reason for failure
'''
@app.route('/drinks/<int:id>', methods = ["DELETE"])
@requires_auth('delete:drinks')
def deleteDrinks(jwt, id):
    try:
        drink = Drink.query.filter(Drink.id == id).one_or_none()

        if drink is None:
            abort(404)

        drink.delete()
        return jsonify({
            "success": True,
            "deleted_drink": id
        }),200
    except:
        db.session.rollback()
        abort(404)
    finally:
        db.session.close()


# Error Handling
'''
Example error handling for unprocessable entity
'''


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422


'''
@TODO implement error handlers using the @app.errorhandler(error) decorator
    each error handler should return (with approprate messages):
             jsonify({
                    "success": False,
                    "error": 404,
                    "message": "resource not found"
                    }), 404

'''

'''
@TODO implement error handler for 404
    error handler should conform to general task above
'''
@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "sucess": False,
        "error": 404,
        "message": "resource not found"
        }),404

@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({
        'sucess': False,
        'error': 500,
        'message': "Internal Server Error"
        }),500
    
@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        'sucess': False,
        'error': 400,
        'message': "Bad Request"
        }),400

@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": 422,
        "message": "unprocessable"
    }), 422


'''
@TODO implement error handler for AuthError
    error handler should conform to general task above
'''
@app.errorhandler(AuthError)
def process_AuthError(error):
    response = jsonify(error.error)
    response.status_code = error.status_code

    return response
