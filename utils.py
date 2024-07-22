# Configure logging
import  logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
log_event = logging.getLogger(__name__)
