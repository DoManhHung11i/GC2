"""Route blueprints. Import order doesn't matter."""
from . import (auth_routes, accounts_routes, config_routes,
               agents_routes, sessions_routes, drive_routes)

ALL_BLUEPRINTS = [
    auth_routes.bp,
    accounts_routes.bp,
    config_routes.bp,
    agents_routes.bp,
    sessions_routes.bp,
    drive_routes.bp,
]
