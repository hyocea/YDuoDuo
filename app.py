import os
import sys
import re
from flask import session
from flask import request, url_for, redirect, flash, jsonify
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import func
from sqlalchemy import Column
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from datetime import datetime

# Determine platform type for database path
WIN = sys.platform.startswith('win')
if WIN:
    prefix = 'sqlite:///'
else:
    prefix = 'sqlite:////'

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = os.path.join(
    app.root_path, 'static', 'product_img')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}


def allowed_file(filename):
    return '.' in filename and filename.rsplit(
        '.', 1)[1].lower() in ALLOWED_EXTENSIONS


app.config['SQLALCHEMY_DATABASE_URI'] = prefix + \
    os.path.join(os.path.dirname(app.root_path), os.getenv('DATABASE_FILE', 'data.db'))

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev')

db = SQLAlchemy(app)

# 初始化 Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)

# 创建关联表
wishlist = db.Table(
    'wishlist',
    db.Column(
        'user_id',
        db.Integer,
        db.ForeignKey('user.id'),
        primary_key=True),
    db.Column(
        'product_id',
        db.Integer,
        db.ForeignKey('product.id'),
        primary_key=True))


# 用户模型
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10))  # 新增角色字段
    wishlist = db.relationship('Product', secondary=wishlist, lazy='subquery',
                               backref=db.backref('liked_by', lazy=True))


# 商品模型
class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False)
    image_url = db.Column(db.String(300))
    stock = db.Column(db.Integer, default=0)


class Cart(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer, default=1)  # 新增数量字段，默认值为1

    product = db.relationship('Product', backref='cart_items')


# 订单模型
class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    products = db.relationship(
        'Product',
        secondary='order_product',
        backref=db.backref(
            'orders',
            lazy=True))
    customer_name = db.Column(db.String(100), nullable=False)  # 订购者的名字
    phone_number = db.Column(db.String(20), nullable=False)  # 订购者的电话
    address = db.Column(db.String(200), nullable=False)  # 订购者的地址
    note = db.Column(db.Text)
    date = db.Column(db.DateTime, default=datetime.utcnow)  # 使用当前日期作为默认值
    status = Column(db.String(20), default='processing')


class OrderProduct(db.Model):
    order_id = db.Column(
        db.Integer,
        db.ForeignKey('order.id'),
        primary_key=True)
    product_id = db.Column(
        db.Integer,
        db.ForeignKey('product.id'),
        primary_key=True)
    quantity = db.Column(db.Integer, nullable=False)


# Create database tables
with app.app_context():
    db.create_all()
    username = 'admin'
    password = 'admin'
    hashed_password = generate_password_hash(password)
    if not User.query.filter_by(username=username).first():
        admin = User(username=username, password=hashed_password, role='admin')
        db.session.add(admin)
        db.session.commit()


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route('/')
def index():
    if current_user.is_authenticated:
        # 获取愿望清单中的商品
        wishlist_products = current_user.wishlist
        recommended_products = set(wishlist_products)

        for product in wishlist_products:
            # 根据产品名称和价格查找相关产品
            similar_products = Product.query.filter(
                Product.name.contains(product.name) |
                ((Product.price >= product.price * 0.8) &
                 (Product.price <= product.price * 1.2))
            ).all()

            recommended_products.update(similar_products)

        # 将推荐产品转换为列表，排序并限制数量
        recommended_products = list(recommended_products)
        recommended_products.sort(key=lambda x: x.price)
        recommended_products = recommended_products[:8]  # 限制显示最多8个商品

        return render_template('index.html', products=recommended_products)
    else:
        # 如果用户未登录，显示所有产品，但仍然限制为最多8个
        products = Product.query.order_by(
            func.random()).limit(8).all()  # 随机选择8个产品
        return render_template('index.html', products=products)

# 登录路由


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()
        if user:
            if check_password_hash(user.password, password):
                if user.role == 'admin':
                    session['is_admin'] = True
                    login_user(user)
                    return redirect(url_for('admin_dashboard'))
                elif user.role == 'merchant':
                    login_user(user)
                    return redirect(url_for('admin_index'))
                elif user.role == 'user':
                    login_user(user)
                    return redirect(url_for('index'))
                else:
                    flash('账户角色无效，请联系管理员。')
            else:
                flash('密码错误，请重试。')
        else:
            flash('用户名不存在。请注册。')
            return redirect(url_for('register'))

    return render_template('login.html')


# 用户注册路由
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # 验证用户名和密码的长度
        if len(username) < 3 or len(username) > 20:
            flash('Username must be between 3 and 20 characters.')
            return redirect(url_for('register'))

        if len(password) < 6 or len(password) > 20:
            flash('Password must be between 6 and 20 characters.')
            return redirect(url_for('register'))

        # 验证密码是否为字母和数字的组合
        if not re.match(
            "^(?=.*[A-Za-z])(?=.*\\d)[A-Za-z\\d]{6,20}$",
                password):
            flash('Password must contain both letters and numbers.')
            return redirect(url_for('register'))

        # 验证用户名是否已经存在
        user_exists = User.query.filter_by(username=username).first()
        if user_exists:
            flash('Username already exists.')
            return redirect(url_for('register'))

        # 验证密码和确认密码是否匹配
        if password != confirm_password:
            flash('Passwords do not match.')
            return redirect(url_for('register'))

        # 创建新用户并保存到数据库
        # 使用 Werkzeug 的 generate_password_hash
        hashed_password = generate_password_hash(password)
        new_user = User(
            username=username,
            password=hashed_password,
            role='user')  # 传递哈希过的密码
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful. Please login.')
        return redirect(url_for('login'))

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


@app.route('/account', methods=['GET'])
@login_required
def admin_dashboard():
    if current_user.role == 'admin':
        users = User.query.all()  # 获取所有用户
        return render_template('account-list.html', users=users)
    else:
        flash('只有管理员才能访问这个页面。')
        return redirect(url_for('index'))


@app.route('/account/create_merchant', methods=['GET', 'POST'])
@login_required
def create_merchant():
    if session.get('is_admin'):
        if request.method == 'POST':
            username = request.form.get('username')
            password = request.form.get('password')
            hashed_password = generate_password_hash(password)
            new_merchant = User(
                username=username,
                password=hashed_password,
                role='merchant')
            db.session.add(new_merchant)
            db.session.commit()
            flash('商家账户创建成功。')
            return redirect(url_for('admin_dashboard'))
        return render_template('add-login.html')
    else:
        return redirect(url_for('login'))


@app.route('/account/delete_user/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if current_user.role == 'admin':
        user_to_delete = User.query.get(user_id)

        # 检查要删除的用户是否是管理员
        if user_to_delete and user_to_delete.role == 'admin':
            flash('管理员账号不能被删除。')
            return redirect(url_for('admin_dashboard'))

        if user_to_delete:
            db.session.delete(user_to_delete)
            db.session.commit()
            flash('用户删除成功。')
        else:
            flash('找不到用户。')
        return redirect(url_for('admin_dashboard'))
    else:
        flash('只有管理员才能执行这个操作。')
        return redirect(url_for('admin_dashboard'))


@app.route('/admin')
def admin_index():
    if session.get('is_admin'):
        products = Product.query.all()  # 获取所有产品
        return render_template('admin_index.html', products=products)
    else:
        return redirect(url_for('login'))  # 如果不是管理员，则重定向到登录页面


@app.route('/add-product', methods=['GET', 'POST'])
def add_product():
    if request.method == 'POST':
        # 获取表单数据
        name = request.form.get('name')
        description = request.form.get('description')
        price = request.form.get('price')
        image = request.files['productImage']
        stock = request.form.get('stock')

        # 检查所有字段是否已填写且图片是否已上传
        if not all([name, description, price, stock, image]):
            flash('所有字段均为必填，包括图片上传。', 'error')
            return render_template('add-product.html')

        # 验证和保存图片
        if image and allowed_file(image.filename):
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))

        else:
            flash('上传的文件不符合要求。', 'error')
            return render_template('add-product.html')

        # 创建新商品
        new_product = Product(
            name=name,
            description=description,
            price=price,
            image_url=filename,
            stock=stock)
        db.session.add(new_product)
        db.session.commit()

        flash('产品添加成功。', 'success')
        return redirect(url_for('admin_index'))
    return render_template('add-product.html')


@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    return render_template('product-single.html', product=product)


@app.route('/delete-product/<int:product_id>')
@login_required
def delete_product(product_id):
    product = Product.query.get_or_404(product_id)
    db.session.delete(product)
    db.session.commit()
    flash('Product successfully deleted', 'success')
    return redirect(url_for('admin_index'))


@app.route('/add-to-cart/<product_id>', methods=['POST'])
@login_required
def add_to_cart(product_id):
    quantity = request.form.get('quantity', type=int)
    cart_item = Cart.query.filter_by(
        user_id=current_user.id,
        product_id=product_id).first()

    if cart_item:
        if cart_item.quantity is None:
            cart_item.quantity = 0
        cart_item.quantity += quantity
    else:
        new_cart_item = Cart(
            user_id=current_user.id,
            product_id=product_id,
            quantity=quantity)
        db.session.add(new_cart_item)

    db.session.commit()
    return redirect(url_for('cart'))


@app.route('/update-cart/<product_id>', methods=['POST'])
@login_required
def update_cart(product_id):
    quantity = request.json.get('quantity')
    cart_item = Cart.query.filter_by(
        user_id=current_user.id,
        product_id=product_id).first()
    if cart_item:
        cart_item.quantity = quantity
        db.session.commit()
    return jsonify({'status': 'success'})


@app.route('/remove-from-cart/<product_id>', methods=['GET'])
@login_required
def remove_from_cart(product_id):
    cart_item = Cart.query.filter_by(
        user_id=current_user.id,
        product_id=product_id).first()
    if cart_item:
        db.session.delete(cart_item)
        db.session.commit()
    return redirect(url_for('cart'))


@app.route('/cart')
@login_required
def cart():
    cart_items = Cart.query.filter_by(user_id=current_user.id).all()
    products_with_quantity = [
        {
            'details': Product.query.get(item.product_id),
            'quantity': item.quantity
        }
        for item in cart_items
    ]

    # 计算总价
    total_price = sum(item['details'].price * item['quantity']
                      for item in products_with_quantity)

    return render_template(
        'cart.html',
        products=products_with_quantity,
        total_price=total_price)


@app.route('/wishlist')
@login_required
def wishlist():
    # 假设 current_user 是当前登录的用户
    return render_template('wishlist.html', products=current_user.wishlist)


@app.route('/add-to-wishlist/<int:product_id>')
@login_required
def add_to_wishlist(product_id):
    products = Product.query.get(product_id)
    if products and current_user.is_authenticated:
        if products not in current_user.wishlist:
            current_user.wishlist.append(products)
            db.session.commit()
    return jsonify(success=True)


@app.route('/remove-from-wishlist/<int:product_id>')
def remove_from_wishlist(product_id):
    if current_user.is_authenticated:
        products = Product.query.get(product_id)
        if products in current_user.wishlist:
            current_user.wishlist.remove(products)
            db.session.commit()
    return jsonify(success=True)


# 提交订单的路由
@app.route('/submit-order', methods=['POST'])
@login_required
def submit_order():
    user_id = current_user.id
    cart_items = Cart.query.filter_by(user_id=user_id).all()

    # 从表单获取数据
    customer_name = request.form.get('customer_name')
    phone_number = request.form.get('phone_number')
    address = request.form.get('address')

    # 确保必填字段不为空
    if not all([customer_name, phone_number, address]):
        flash(
            'All fields are required. Please fill out the form completely.',
            'error')
        return redirect(url_for('checkout'))  # 假设 order_form 是提交订单的表单页面

    # 获取当前当地日期时间
    current_date = datetime.now()

    # 创建新订单并包含表单中的信息
    new_order = Order(
        user_id=user_id,
        customer_name=customer_name,
        phone_number=phone_number,
        address=address,
        date=current_date
    )
    db.session.add(new_order)
    db.session.flush()  # 提前获取新订单的ID

    # 将购物车中的商品添加到订单产品关联表
    for item in cart_items:
        order_product = OrderProduct(
            order_id=new_order.id,
            product_id=item.product_id,
            quantity=item.quantity)
        db.session.add(order_product)

    db.session.commit()
    return redirect(url_for('order_success'))

# 其他路由保持不变


@app.route('/admin/update-order-status/<int:order_id>', methods=['POST'])
def update_order_status(order_id):
    new_status = request.form.get('new_status')
    order = Order.query.get_or_404(order_id)
    order.status = new_status
    db.session.commit()
    flash('Order status updated successfully!', 'success')
    return redirect(url_for('order_details', order_id=order_id))


# 订单提交成功页面
@app.route('/order-success')
@login_required
def order_success():
    return redirect(url_for('my_orders'))


@app.route('/my_orders')
@login_required
def my_orders():
    user_orders = Order.query.filter_by(user_id=current_user.id).all()
    orders_with_total = []

    for order in user_orders:
        order_products = OrderProduct.query.filter_by(order_id=order.id).all()
        total_price = sum(
            op.quantity *
            Product.query.get(
                op.product_id).price for op in order_products)
        orders_with_total.append({'order': order, 'total_price': total_price})

    return render_template('order.html', orders_with_total=orders_with_total)


def get_cart_items():
    user_id = current_user.id  # 假设您使用 Flask-Login 来管理用户会话
    cart_items = Cart.query.filter_by(user_id=user_id).all()
    return cart_items


@app.route('/checkout')
@login_required
def checkout():
    out_of_stock_items = []
    cart_items = get_cart_items()
    total_price = 0

    for item in cart_items:
        product = Product.query.get(item.product_id)
        if product and product.stock < item.quantity:
            out_of_stock_items.append(product.name)
        else:
            item.total = product.price * item.quantity
            total_price += item.total

    if out_of_stock_items:
        flash(
            f"Sorry, the following items are out of stock: {', '.join(out_of_stock_items)}",
            'warning')
        return redirect(url_for('cart'))  # 重定向回购物车页面

    return render_template('checkout.html', cart_items=cart_items, total_price=total_price)


# 商家查看订单的路由
@app.route('/admin/orders')
def admin_orders():
    orders = Order.query.all()
    order_details = []
    for order in orders:
        user = User.query.get(order.user_id)
        order_details.append({'order': order,
                              'username': user.username,
                              'date': order.date.strftime('%Y-%m-%d')
                              })

    return render_template('order-list.html', orders=order_details)


@app.route('/admin/order-details/<int:order_id>', methods=['GET', 'POST'])
def order_details(order_id):
    order = Order.query.get_or_404(order_id)

    if request.method == 'POST':
        new_status = request.form.get('new_status')
        if new_status:
            order.status = new_status
            db.session.commit()
            flash('Order status updated successfully!', 'success')
            return redirect(url_for('order_details', order_id=order_id))

    order_products = OrderProduct.query.filter_by(order_id=order_id).all()
    product_details = []
    total_price = 0  # 初始化总价

    for op in order_products:
        product = Product.query.get(op.product_id)
        product_details.append({'quantity': op.quantity, 'product': product})
        total_price += op.quantity * product.price  # 累加总价

    return render_template(
        'order-details.html',
        order=order,
        product_details=product_details,
        total_price=total_price)


@app.route('/shop', methods=['GET'])
@login_required
def shop():
    search_query = request.args.get('search', '')
    price_filter = request.args.get('price_filter', 'all')

    query = Product.query
    if search_query:
        query = query.filter(Product.name.ilike(f'%{search_query}%'))

    if price_filter != 'all':
        min_price, max_price = map(int, price_filter.split('-'))
        query = query.filter(
            Product.price >= min_price,
            Product.price <= max_price)

    filtered_products = query.all()
    return render_template('shop.html', products=filtered_products)


@app.errorhandler(401)
def custom_401(error):
    flash("您需要登录才能访问这个页面。")  # 闪现一条消息
    return redirect(url_for('login'))


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
