import logging

from django.conf import settings
from django.db import connection

logger = logging.getLogger(__name__)


class QueryCountMiddleware:
    """
    Middleware pre monitorovanie počtu database queries v development mode.
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Iba pre development mode
        if not settings.DEBUG:
            return self.get_response(request)

        # Reset query count pre tento request
        initial_queries = len(connection.queries)

        response = self.get_response(request)

        # Analyzuj queries po vykonaní requestu
        query_count = len(connection.queries) - initial_queries

        self._log_query_metrics(request, query_count)

        return response

    def _log_query_metrics(self, request, query_count):
        """Loguje query metriky s rôznymi úrovňami závažnosti."""

        # Thresholdy pre rôzne úrovne
        thresholds = {"HIGH": 50, "MEDIUM": 25, "LOW": 10}

        extra_context = {
            "request_path": request.path,
            "request_method": request.method,
            "user_id": request.user.id if request.user.is_authenticated else None,
            "query_count": query_count,
            "action": "query_count_monitoring",
            "component": "QueryCountMiddleware",
        }

        # Log podľa závažnosti
        if query_count >= thresholds["HIGH"]:
            logger.warning(
                "🚨 HIGH query count detected",
                extra={
                    **extra_context,
                    "severity": "high",
                    "threshold": thresholds["HIGH"],
                    "recommendation": "Check for N+1 queries and optimize database calls",
                },
            )
        elif query_count >= thresholds["MEDIUM"]:
            logger.info(
                "⚠️ Medium query count",
                extra={
                    **extra_context,
                    "severity": "medium",
                    "threshold": thresholds["MEDIUM"],
                },
            )
        elif query_count >= thresholds["LOW"]:
            logger.debug(
                "ℹ️ Normal query count",
                extra={
                    **extra_context,
                    "severity": "low",
                    "threshold": thresholds["LOW"],
                },
            )

        # Debug info pre vývojárov
        if settings.DEBUG and query_count > 0:
            self._log_detailed_queries(request, query_count)

    def _log_detailed_queries(self, request, query_count):
        """Loguje detailné informácie o queries pre development."""
        unique_tables = set()
        slow_queries = []

        for query in connection.queries:
            # Extrahuj názov tabuľky (jednoduchá heuristika)
            sql = query["sql"].lower()
            if "from " in sql:
                table_part = sql.split("from ")[1].split(" ")[0]
                unique_tables.add(table_part.strip('"`'))

            # Identifikuj pomalé queries (> 100ms)
            if float(query.get("time", 0)) > 0.1:  # 100ms
                slow_queries.append(
                    {
                        "time": query["time"],
                        "sql_preview": (
                            query["sql"][:100] + "..."
                            if len(query["sql"]) > 100
                            else query["sql"]
                        ),
                    }
                )

        # Log detailov
        logger.debug(
            "Query monitoring details",
            extra={
                "request_path": request.path,
                "total_queries": query_count,
                "unique_tables_accessed": list(unique_tables),
                "slow_queries_count": len(slow_queries),
                "slow_queries": slow_queries[:3],  # Prvé 3 pomalé queries
                "total_query_time": sum(float(q["time"]) for q in connection.queries),
                "action": "query_monitoring_details",
                "component": "QueryCountMiddleware",
            },
        )


class QueryDebugMiddleware:
    """
    Middleware pre detailné debugovanie queries (iba pre lokálny vývoj).
    """

    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # Iba pre lokálny development
        if not settings.DEBUG or not settings.QUERY_DEBUG_ENABLED:
            return self.get_response(request)

        from django.db import reset_queries

        reset_queries()

        response = self.get_response(request)

        # Zobraz všetky queries v konzole
        self._print_query_debug_info(request)

        return response

    def _print_query_debug_info(self, request):
        """Vypíše detailné query info do konzoly."""
        queries = connection.queries
        total_time = sum(float(q["time"]) for q in queries)

        print(f"\n{'='*60}")
        print(f"🔍 QUERY DEBUG: {request.method} {request.path}")
        print(f"{'='*60}")
        print(f"Total queries: {len(queries)}")
        print(f"Total time: {total_time:.3f}s")
        print(f"{'-'*60}")

        for i, query in enumerate(queries, 1):
            print(f"{i}. [{query['time']}s] {query['sql']}")

        print(f"{'='*60}\n")
