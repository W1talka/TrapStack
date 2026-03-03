from flask import Flask
from dotenv import load_dotenv

from app.config import Config

load_dotenv()


def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    from app.routes.dashboard import bp as dashboard_bp
    from app.routes.decisions import bp as decisions_bp
    from app.routes.alerts import bp as alerts_bp
    from app.routes.config_editor import bp as config_bp
    from app.routes.logs import bp as logs_bp
    from app.routes.scenarios import bp as scenarios_bp

    app.register_blueprint(dashboard_bp)
    app.register_blueprint(decisions_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(config_bp)
    app.register_blueprint(logs_bp)
    app.register_blueprint(scenarios_bp)

    return app
