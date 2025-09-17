import uvloop
import asyncio
import sys
import uvicorn
from fastapi import FastAPI

import app.routers.balance_routers
from app.logging_config import configure_logging
from app.routers.admin_routers import admin_router
from app.routers.auth_routers import auth_router
from app.routers.security_routers import token_router
from app.routers.user_routers import router
from settings import DEBUG

configure_logging()
app = FastAPI()
app.include_router(router)
app.include_router(admin_router)
app.include_router(token_router)
app.include_router(auth_router)

def setup_uvloop():
    """Setup uvloop as the main event loop."""
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())


if __name__ == '__main__':
    setup_uvloop()

    if 'shell' in sys.argv:
        from IPython import start_ipython

        start_ipython(argv=["--TerminalIPythonApp.exec_lines=['import asyncio', 'import uvloop', 'uvloop.install()']"])
    else:
        uvicorn.run('main:app', host='0.0.0.0', port=8000, reload=DEBUG, loop='uvloop')
