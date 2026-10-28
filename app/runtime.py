"""Process-wide singletons shared by routes, the syslog receiver and the worker."""
from .config import settings
from .det_rules import RuleStore
from .enrichment import Enricher
from types import SimpleNamespace

from .live import LiveHub
from .threatintel import TIIndex
from .worker import Worker

rule_store = RuleStore(settings.rules_dir)
enricher = Enricher()
hub = LiveHub()
ti_index = TIIndex()                         # threat-intel lookup, rebuilt after every feed sync
shared = SimpleNamespace(watchlists={})     # name -> set of lower-case values; replaced (never mutated) by the worker
worker = Worker(rule_store, enricher, hub, ti_index, shared)
