import logging
from functools import wraps

from flask import Flask, request, jsonify, g
from flask_jwt_extended import JWTManager, verify_jwt_in_request, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from marshmallow import Schema, fields, validate, ValidationError
from sqlalchemy.exc import IntegrityError
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['JWT_SECRET_KEY'] = 'change-this-in-production'

db = SQLAlchemy(app)
jwt = JWTManager(app)
logger = logging.getLogger(__name__)


# ------------------------------------------------------------------
# Models
# ------------------------------------------------------------------

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(50), nullable=False)


class Warehouse(db.Model):
    __tablename__ = 'warehouses'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)


class Product(db.Model):
    __tablename__ = 'products'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    sku = db.Column(db.String(100), unique=True, nullable=False)
    price = db.Column(db.Float, nullable=False)
    warehouse_id = db.Column(db.Integer, db.ForeignKey('warehouses.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class Inventory(db.Model):
    __tablename__ = 'inventory'

    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    warehouse_id = db.Column(db.Integer, db.ForeignKey('warehouses.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)


# ------------------------------------------------------------------
# Input schema
# ------------------------------------------------------------------

class CreateProductSchema(Schema):
    name = fields.Str(required=True, validate=validate.Length(min=1, max=255))
    sku = fields.Str(
        required=True,
        validate=[
            validate.Length(min=1, max=100),
            validate.Regexp(
                r'^[A-Za-z0-9\-_]+$',
                error='SKU may only contain letters, numbers, hyphens, and underscores'
            )
        ]
    )
    price = fields.Float(required=True, validate=validate.Range(min=0.01, error='Price must be greater than zero'))
    warehouse_id = fields.Int(required=True)
    initial_quantity = fields.Int(required=True, validate=validate.Range(min=0, error='Quantity cannot be negative'))


_create_product_schema = CreateProductSchema()


# ------------------------------------------------------------------
# Auth decorator
# ------------------------------------------------------------------

def require_role(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = User.query.get(user_id)

            if user is None:
                return jsonify({'error': 'User not found'}), 401

            if user.role not in roles:
                return jsonify({'error': 'You do not have permission to perform this action'}), 403

            g.current_user = user
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ------------------------------------------------------------------
# Route
# ------------------------------------------------------------------

@app.route('/api/products', methods=['POST'])
@require_role('admin', 'inventory_manager')
def create_product():
    if not request.is_json:
        return jsonify({'error': 'Content-Type must be application/json'}), 415

    raw = request.get_json(silent=True)
    if raw is None:
        return jsonify({'error': 'Request body is missing or contains malformed JSON'}), 400

    try:
        data = _create_product_schema.load(raw)
    except ValidationError as err:
        return jsonify({'error': 'Validation failed', 'details': err.messages}), 400

    existing = Product.query.filter_by(sku=data['sku']).first()
    if existing:
        return jsonify({'error': 'A product with this SKU already exists'}), 409

    warehouse = Warehouse.query.get(data['warehouse_id'])
    if warehouse is None:
        return jsonify({'error': 'Warehouse not found'}), 404

    try:
        product = Product(
            name=data['name'],
            sku=data['sku'],
            price=data['price'],
            warehouse_id=data['warehouse_id'],
            created_by=g.current_user.id
        )
        db.session.add(product)
        db.session.flush()

        inventory = Inventory(
            product_id=product.id,
            warehouse_id=data['warehouse_id'],
            quantity=data['initial_quantity']
        )
        db.session.add(inventory)
        db.session.commit()

    except IntegrityError as exc:
        db.session.rollback()
        logger.error(
            'IntegrityError on product creation: sku=%s user=%s error=%s',
            data.get('sku'), g.current_user.id, str(exc)
        )
        return jsonify({'error': 'A database constraint was violated. Check that the SKU and warehouse are valid.'}), 409

    except Exception:
        db.session.rollback()
        logger.exception(
            'Unexpected error on product creation: sku=%s user=%s',
            data.get('sku'), g.current_user.id
        )
        return jsonify({'error': 'An unexpected error occurred. Please try again later.'}), 500

    logger.info(
        'Product created: id=%s sku=%s warehouse_id=%s user=%s',
        product.id, product.sku, product.warehouse_id, g.current_user.id
    )

    return jsonify({
        'message': 'Product created successfully',
        'product': {
            'id': product.id,
            'name': product.name,
            'sku': product.sku,
            'price': product.price,
            'warehouse_id': product.warehouse_id,
            'initial_quantity': inventory.quantity,
            'created_by': product.created_by,
            'created_at': product.created_at.isoformat()
        }
    }), 201


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)
