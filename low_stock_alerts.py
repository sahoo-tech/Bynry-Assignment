"""
GET /api/companies/{company_id}/alerts/low-stock

Assumptions:
- warehouse_inventory.reorder_point = per-row threshold (NULL → category/global default)
- Only products with a SALE transaction in the last RECENT_SALE_DAYS are included
- Preferred active supplier scoped to the company's supplier list
- Available stock = quantity_on_hand - quantity_reserved
"""

import logging
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, jsonify, g
from flask_jwt_extended import JWTManager, verify_jwt_in_request, get_jwt_identity
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func, and_
from sqlalchemy.exc import SQLAlchemyError

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///inventory.db'
app.config['JWT_SECRET_KEY'] = 'change-this-in-production'

db = SQLAlchemy(app)
jwt = JWTManager(app)
logger = logging.getLogger(__name__)

RECENT_SALE_DAYS = 30
MAX_DAYS_STOCKOUT = 999

# Fallback thresholds when warehouse_inventory.reorder_point is NULL
CATEGORY_THRESHOLDS = {
    'electronics':  50,
    'perishable':  100,
    'raw_material': 200,
    'consumable':   75,
    'spare_parts':  30,
}
DEFAULT_THRESHOLD = 10


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Company(db.Model):
    __tablename__ = 'companies'
    id        = db.Column(db.Integer, primary_key=True)
    name      = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=False, default=True)


class Warehouse(db.Model):
    __tablename__ = 'warehouses'
    id         = db.Column(db.Integer, primary_key=True)
    company_id = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    name       = db.Column(db.String(255), nullable=False)
    is_active  = db.Column(db.Boolean, nullable=False, default=True)


class Product(db.Model):
    __tablename__ = 'products'
    id        = db.Column(db.Integer, primary_key=True)
    name      = db.Column(db.String(255), nullable=False)
    sku       = db.Column(db.String(100), unique=True, nullable=False)
    category  = db.Column(db.String(100))
    is_active = db.Column(db.Boolean, nullable=False, default=True)


class WarehouseInventory(db.Model):
    __tablename__ = 'warehouse_inventory'
    id                = db.Column(db.Integer, primary_key=True)
    warehouse_id      = db.Column(db.Integer, db.ForeignKey('warehouses.id'), nullable=False)
    product_id        = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    quantity_on_hand  = db.Column(db.Numeric(15, 4), nullable=False, default=0)
    quantity_reserved = db.Column(db.Numeric(15, 4), nullable=False, default=0)
    reorder_point     = db.Column(db.Numeric(15, 4))  # NULL = use category/global default


class InventoryTransaction(db.Model):
    __tablename__ = 'inventory_transactions'
    id             = db.Column(db.BigInteger, primary_key=True)
    warehouse_id   = db.Column(db.Integer, db.ForeignKey('warehouses.id'), nullable=False)
    product_id     = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    txn_type       = db.Column(db.String(50), nullable=False)
    quantity_delta = db.Column(db.Numeric(15, 4), nullable=False)  # negative = outbound
    performed_at   = db.Column(db.DateTime(timezone=True), nullable=False, default=datetime.utcnow)


class Supplier(db.Model):
    __tablename__ = 'suppliers'
    id        = db.Column(db.Integer, primary_key=True)
    name      = db.Column(db.String(255), nullable=False)
    email     = db.Column(db.String(255))
    is_active = db.Column(db.Boolean, nullable=False, default=True)


class CompanySupplier(db.Model):
    __tablename__ = 'company_suppliers'
    id          = db.Column(db.Integer, primary_key=True)
    company_id  = db.Column(db.Integer, db.ForeignKey('companies.id'), nullable=False)
    supplier_id = db.Column(db.Integer, db.ForeignKey('suppliers.id'), nullable=False)


class SupplierProduct(db.Model):
    __tablename__ = 'supplier_products'
    id             = db.Column(db.Integer, primary_key=True)
    supplier_id    = db.Column(db.Integer, db.ForeignKey('suppliers.id'), nullable=False)
    product_id     = db.Column(db.Integer, db.ForeignKey('products.id'), nullable=False)
    is_preferred   = db.Column(db.Boolean, nullable=False, default=False)
    effective_from = db.Column(db.Date, nullable=False)
    effective_to   = db.Column(db.Date)  # NULL = currently active


class User(db.Model):
    __tablename__ = 'users'
    id       = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    role     = db.Column(db.String(50), nullable=False)


# ---------------------------------------------------------------------------
# Auth
# ---------------------------------------------------------------------------

def require_role(*roles):
    def decorator(fn):
        @wraps(fn)
        def wrapper(*args, **kwargs):
            verify_jwt_in_request()
            user = User.query.get(get_jwt_identity())
            if user is None:
                return jsonify({'error': 'User not found'}), 401
            if user.role not in roles:
                return jsonify({'error': 'Forbidden'}), 403
            g.current_user = user
            return fn(*args, **kwargs)
        return wrapper
    return decorator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _resolve_threshold(inv: WarehouseInventory, product: Product) -> float:
    """Per-row reorder_point → category default → global default."""
    if inv.reorder_point is not None:
        return float(inv.reorder_point)
    return float(CATEGORY_THRESHOLDS.get((product.category or '').lower(), DEFAULT_THRESHOLD))


def _avg_daily_sales(warehouse_id: int, product_id: int, since: datetime) -> float:
    """Average units sold per day over the recent window."""
    total = db.session.query(
        func.coalesce(func.sum(func.abs(InventoryTransaction.quantity_delta)), 0)
    ).filter(
        InventoryTransaction.warehouse_id == warehouse_id,
        InventoryTransaction.product_id  == product_id,
        InventoryTransaction.txn_type    == 'SALE',
        InventoryTransaction.performed_at >= since,
    ).scalar()
    return float(total) / RECENT_SALE_DAYS


def _days_until_stockout(available: float, daily_rate: float):
    """Returns int days or None if rate is zero (unknown velocity)."""
    if daily_rate <= 0:
        return None
    return min(round(available / daily_rate), MAX_DAYS_STOCKOUT)


def _get_supplier(product_id: int, company_id: int):
    """Returns the preferred active supplier for the product, scoped to the company."""
    company_supplier_ids = (
        db.session.query(CompanySupplier.supplier_id)
        .filter(CompanySupplier.company_id == company_id)
        .subquery()
    )
    base = (
        db.session.query(Supplier)
        .join(SupplierProduct, SupplierProduct.supplier_id == Supplier.id)
        .filter(
            SupplierProduct.product_id == product_id,
            SupplierProduct.effective_to.is_(None),
            Supplier.is_active == True,
            Supplier.id.in_(company_supplier_ids),
        )
    )
    return base.filter(SupplierProduct.is_preferred == True).first() or base.first()


# ---------------------------------------------------------------------------
# Endpoint
# ---------------------------------------------------------------------------

@app.route('/api/companies/<int:company_id>/alerts/low-stock', methods=['GET'])
@require_role('admin', 'inventory_manager', 'viewer')
def get_low_stock_alerts(company_id: int):
    company = Company.query.filter_by(id=company_id, is_active=True).first()
    if company is None:
        return jsonify({'error': f'Company {company_id} not found or inactive'}), 404

    warehouses = Warehouse.query.filter_by(company_id=company_id, is_active=True).all()
    if not warehouses:
        return jsonify({'alerts': [], 'total_alerts': 0}), 200

    warehouse_ids   = [w.id for w in warehouses]
    warehouse_by_id = {w.id: w for w in warehouses}
    sales_since     = datetime.now(timezone.utc) - timedelta(days=RECENT_SALE_DAYS)

    # Sub-select: only (warehouse, product) pairs with at least one recent sale
    recent_sales = (
        db.session.query(
            InventoryTransaction.warehouse_id,
            InventoryTransaction.product_id,
        )
        .filter(
            InventoryTransaction.warehouse_id.in_(warehouse_ids),
            InventoryTransaction.txn_type    == 'SALE',
            InventoryTransaction.performed_at >= sales_since,
        )
        .distinct()
        .subquery()
    )

    try:
        rows = (
            db.session.query(WarehouseInventory, Product)
            .join(Product, Product.id == WarehouseInventory.product_id)
            .join(
                recent_sales,
                and_(
                    recent_sales.c.warehouse_id == WarehouseInventory.warehouse_id,
                    recent_sales.c.product_id   == WarehouseInventory.product_id,
                )
            )
            .filter(
                WarehouseInventory.warehouse_id.in_(warehouse_ids),
                Product.is_active == True,
            )
            .all()
        )
    except SQLAlchemyError:
        logger.exception('low_stock_alerts DB error company_id=%s', company_id)
        return jsonify({'error': 'Database error. Please try again later.'}), 503

    alerts = []
    for inv, product in rows:
        available  = float(inv.quantity_on_hand) - float(inv.quantity_reserved)
        threshold  = _resolve_threshold(inv, product)

        if available >= threshold:
            continue

        try:
            daily_rate = _avg_daily_sales(inv.warehouse_id, product.id, sales_since)
        except SQLAlchemyError:
            logger.exception('low_stock_alerts: sales velocity error product_id=%s', product.id)
            daily_rate = 0

        try:
            supplier = _get_supplier(product.id, company_id)
        except SQLAlchemyError:
            logger.exception('low_stock_alerts: supplier lookup error product_id=%s', product.id)
            supplier = None

        alerts.append({
            'product_id':          product.id,
            'product_name':        product.name,
            'sku':                 product.sku,
            'warehouse_id':        inv.warehouse_id,
            'warehouse_name':      warehouse_by_id[inv.warehouse_id].name,
            'current_stock':       round(available, 4),
            'threshold':           round(threshold, 4),
            'days_until_stockout': _days_until_stockout(available, daily_rate),
            'supplier': {
                'id':            supplier.id,
                'name':          supplier.name,
                'contact_email': supplier.email,
            } if supplier else None,
        })

    # Most urgent (fewest days remaining) first; unknown velocity sorted last
    alerts.sort(key=lambda a: (a['days_until_stockout'] is None, a['days_until_stockout'] or 0))

    logger.info('low_stock_alerts company_id=%s alerts=%d', company_id, len(alerts))
    return jsonify({'alerts': alerts, 'total_alerts': len(alerts)}), 200


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=False)
