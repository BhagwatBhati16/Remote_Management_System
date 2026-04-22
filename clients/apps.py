from django.apps import AppConfig


class ClientsConfig(AppConfig):
    default_auto_field = "django.db.models.BigAutoField"
    name = "clients"

    def ready(self):
        """Register a post_migrate signal to clean up stale sessions after startup."""
        from django.db.models.signals import post_migrate
        post_migrate.connect(_cleanup_stale_sessions, sender=self)


def _cleanup_stale_sessions(sender, **kwargs):
    """Clean up stale VNC/SSH session records whose processes died (e.g. after server restart)."""
    import logging
    logger = logging.getLogger(__name__)

    try:
        from .models import VNCSession, SSHSession
        from .utils import pid_alive

        stale_vnc = 0
        for session in VNCSession.objects.all():
            if not pid_alive(session.pid):
                logger.info("Cleaning stale VNCSession (pid=%s, client=%s)", session.pid, session.client_id)
                session.delete()
                stale_vnc += 1

        stale_ssh = 0
        for session in SSHSession.objects.all():
            if not session.pid or not pid_alive(session.pid):
                logger.info("Cleaning stale SSHSession (pid=%s, client=%s)", session.pid, session.client_id)
                session.delete()
                stale_ssh += 1

        if stale_vnc or stale_ssh:
            logger.info("Startup cleanup: removed %d stale VNC + %d stale SSH sessions.", stale_vnc, stale_ssh)
    except Exception as exc:
        # Don't block startup if DB isn't ready (e.g. during migrations)
        logger.debug("Session cleanup skipped: %s", exc)

