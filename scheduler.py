from apscheduler.schedulers.background import BackgroundScheduler
from database import get_db, get_cursor
from reddit_scanner import scan_reddit
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def scan_all_registered():
    logger.info("Auto-scan started...")

    conn = get_db()
    cursor = get_cursor(conn)

    # NEWEST FIRST (priority scan)
    cursor.execute("SELECT * FROM registered_content ORDER BY created_at DESC")
    all_content = cursor.fetchall()

    cursor.close()
    conn.close()

    if not all_content:
        logger.info("No registered content to scan.")
        return

    for content in all_content:
        logger.info(f"Scanning for: {content['name']}")

        matches = scan_reddit(content["phash"], content["name"])

        if not matches:
            logger.info(f"No new matches for: {content['name']}")
            continue

        conn = get_db()
        cursor = get_cursor(conn)

        for match in matches:

            # ✅ FIX 1: Postgres syntax (%s instead of ?)
            cursor.execute(
                "SELECT id FROM flagged_content WHERE source_url = %s",
                (match["source_url"],)
            )
            existing = cursor.fetchone()

            if not existing:
                # ✅ FIX 2: include user_id
                cursor.execute("""
                    INSERT INTO flagged_content 
                    (registered_id, user_id, content_name, platform, source_url, post_title, match_score, detection_method, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    content["id"],
                    content["user_id"],   # 🔥 CRITICAL FIX
                    content["name"],
                    "Reddit",
                    match["source_url"],
                    match["post_title"],
                    match["match_score"],
                    match["detection_method"],
                    "Pending"
                ))

                logger.info(f"New match saved: {match['source_url']}")

        conn.commit()
        cursor.close()
        conn.close()

    logger.info("Auto-scan completed.")


def start_scheduler():
    scheduler = BackgroundScheduler()

    scheduler.add_job(
        scan_all_registered,
        trigger="interval",
        minutes=15,   # ✅ fixed interval (no overlap)
        id="auto_scan",
        replace_existing=True
    )

    scheduler.start()
    logger.info("Background scheduler started — scanning every 15 minutes.")

    return scheduler
