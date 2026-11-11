"""Alert engine (mục 6.3) cho hệ thống 2 node.

Node bồn (tank) đo mực nước; node ống (pipe) đo lưu lượng và điều khiển bơm. Hai node cùng một site tạo thành một
hệ thống, nên nhiều quy tắc cần dữ liệu của node kia (engine giữ trạng thái chung theo site, dữ liệu quá 60 giây coi là
"không biết" và quy tắc phụ thuộc sẽ không kết luận):

  Node bồn: LOW_LEVEL (mực thấp; nếu auto_mode thì bật bơm ở node ống), HIGH_LEVEL (mực cao; ngắt bơm ở node ống),
            LEAK_SUSPECT (mực giảm quá r cm/phút khi bơm tắt, trạng thái bơm lấy từ node ống).
  Node ống: LEAK_SUSPECT (lưu lượng >= leak_flow_lpm khi bơm tắt, liên tục quá leak_minutes, ngoài giờ dùng nước),
            PUMP_NO_RISE (bơm chạy quá T giây mà mực nước ở node bồn không tăng >= x%: ngắt bơm, node ống sang Fault).
  Cả hai:   DEVICE_OFFLINE.

Vòng đời cảnh báo: open -> ack -> closed. Mỗi (thiết bị, loại) chỉ có tối đa 1 cảnh báo đang mở (open/ack). Sau khi
đóng, 'cooldown_s' (mặc định 300) phải trôi qua mới được mở cảnh báo mới cùng loại.

Thời gian của quy tắc telemetry tính theo 'ts' của mẫu (giờ sự kiện), nên đồng bộ NTP là bắt buộc. Hành động bảo vệ
(ngắt bơm, chuyển Fault) và lệnh tự động chỉ chạy với mẫu 'còn mới' (<= 30 giây) để dữ liệu gửi bù sau khi mất mạng
không kích hoạt bơm. Hành động bảo vệ không bị cooldown chặn (cooldown chỉ giới hạn việc sinh cảnh báo). Trạng thái
cửa sổ/bộ đếm nằm trong bộ nhớ (mất khi restart). Giả định 1 tiến trình; mọi thao tác DB của engine được tuần tự hóa
bằng _engine_lock."""
import json
import logging
import statistics
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import commands, device_params
from .audit import write_audit
from .db import session_scope, utcnow
from .errors import InvalidInput, PublishError
from .events import emit
from .lifecycle import Conflict
from .models import Alert, AlertRule, Device

log = logging.getLogger("alerts")

ALERT_TYPES = ("LOW_LEVEL", "HIGH_LEVEL", "LEAK_SUSPECT", "PUMP_NO_RISE", "DEVICE_OFFLINE")
SEVERITIES = ("warning", "critical")

# Quy tắc mặc định theo loại node (sửa được qua PUT /api/devices/{id}/alert-rules). Ngưỡng low_pct, high_pct, auto_mode,
# leak_flow_lpm, leak_minutes KHÔNG nằm ở đây mà ở cấu hình thiết bị (device_configs), vì firmware cũng dùng chúng.
_OFFLINE = {"severity": "warning", "params": {"cooldown_s": 300}}
RULES_BY_TYPE: dict[str, dict[str, dict]] = {
    "tank": {
        "LOW_LEVEL": {"severity": "warning",
                      "params": {"min_duration_s": 10, "hysteresis_pct": 5, "cooldown_s": 300}},
        "HIGH_LEVEL": {"severity": "warning",
                       "params": {"min_duration_s": 0, "hysteresis_pct": 5, "cooldown_s": 300}},
        "LEAK_SUSPECT": {"severity": "critical",
                         "params": {"window_min": 5, "rate_cm_per_min": 0.3, "settle_s": 30, "cooldown_s": 300}},
        "DEVICE_OFFLINE": _OFFLINE,
    },
    "pipe": {
        # usage_start_h/usage_end_h: khung giờ dùng nước bình thường (giờ địa phương, [start, end)); start == end = không
        # cấu hình, luôn kiểm tra. utc_offset_h: múi giờ địa phương so với UTC (Việt Nam = 7).
        "LEAK_SUSPECT": {"severity": "critical",
                         "params": {"clear_s": 30, "usage_start_h": 0, "usage_end_h": 0, "utc_offset_h": 7,
                                    "cooldown_s": 300}},
        "PUMP_NO_RISE": {"severity": "critical",
                         "params": {"rise_window_s": 60, "min_rise_pct": 1.0, "cooldown_s": 300}},
        "DEVICE_OFFLINE": _OFFLINE,
    },
}
PARAM_BOUNDS = {
    "min_duration_s": (0, 3600), "hysteresis_pct": (0, 50), "cooldown_s": (0, 86400),
    "window_min": (1, 60), "rate_cm_per_min": (0.01, 10), "settle_s": (0, 600),
    "clear_s": (0, 3600), "usage_start_h": (0, 24), "usage_end_h": (0, 24), "utc_offset_h": (-12, 14),
    "rise_window_s": (10, 1800), "min_rise_pct": (0, 100),
}

ACTION_MAX_AGE_S = 30       # chỉ hành động với mẫu mới hơn mức này
GAP_RESET_S = 120           # hở dữ liệu lâu hơn thì bỏ cửa sổ/bộ đếm đang theo dõi
PEER_MAX_AGE_S = 60         # dữ liệu của node kia cũ hơn mức này coi như không biết
FLOW_EPS = 0.05             # L/phút coi như bằng 0
SAFETY_THROTTLE_S = 30      # tối thiểu giữa 2 lần gửi lệnh ngắt bơm tự động cho cùng thiết bị
_CACHE_TTL_S = 30.0

_engine_lock = threading.Lock()
_publisher: commands.Publisher | None = None
_executor: ThreadPoolExecutor | None = None


def set_publisher(publisher) -> None:
    global _publisher
    _publisher = publisher


def _submit(fn) -> None:
    """Chạy hành động (publish MQTT) ở thread riêng: publish chờ PUBACK, mà PUBACK lại do chính thread mạng
    của paho xử lý, nên gọi trực tiếp trong callback on_message sẽ tự chặn (deadlock tới timeout)."""
    global _executor
    if _executor is None:
        _executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="alert-actions")
    _executor.submit(fn)


def shutdown() -> None:
    if _executor is not None:
        _executor.shutdown(wait=False, cancel_futures=True)


@dataclass(frozen=True)
class Sample:
    device_id: int
    ts: datetime                        # naive UTC, giờ thiết bị
    level_pct: float | None = None      # chỉ node bồn
    flow_lpm: float | None = None       # chỉ node ống
    pump_on: bool | None = None         # chỉ node ống


@dataclass
class RuleView:
    id: int
    type: str
    enabled: bool
    severity: str
    params: dict


@dataclass(frozen=True)
class _Peer:
    id: int
    code: str
    type: str


@dataclass
class _DevState:
    last_ts: datetime | None = None
    low_since: datetime | None = None           # node bồn
    high_since: datetime | None = None
    leak_win: deque = field(default_factory=deque)      # (ts, level_pct) khi bơm tắt và đã ổn định
    leak_since: datetime | None = None          # node ống: bắt đầu có dòng chảy khi bơm tắt
    leak_clear_since: datetime | None = None
    rise_since: datetime | None = None          # node ống: bắt đầu theo dõi mực nước khi bơm chạy
    rise_ref: float | None = None

    def reset_windows(self) -> None:
        self.low_since = self.high_since = self.leak_since = self.leak_clear_since = None
        self.rise_since = self.rise_ref = None
        self.leak_win.clear()


@dataclass
class _SiteState:
    """Dữ liệu mới nhất của hai node trong cùng site, để quy tắc của node này dùng dữ liệu của node kia."""
    level: float | None = None
    level_ts: datetime | None = None
    pump_on: bool | None = None
    pump_ts: datetime | None = None
    pump_off_since: datetime | None = None

    def set_level(self, ts: datetime, level: float) -> None:
        self.level, self.level_ts = level, ts

    def set_pump(self, ts: datetime, on: bool) -> None:
        if self.pump_ts is not None and (ts - self.pump_ts).total_seconds() > PEER_MAX_AGE_S:
            self.pump_off_since = None          # đã mất dấu trạng thái bơm một lúc: tính lại thời gian bơm tắt
        if on:
            self.pump_off_since = None
        elif self.pump_off_since is None:
            self.pump_off_since = ts
        self.pump_on, self.pump_ts = on, ts

    def level_at(self, ts: datetime) -> float | None:
        if self.level_ts is None or abs((ts - self.level_ts).total_seconds()) > PEER_MAX_AGE_S:
            return None
        return self.level

    def pump_at(self, ts: datetime) -> bool | None:
        """True/False nếu biết trạng thái bơm gần đây, None nếu không biết."""
        if self.pump_ts is None or abs((ts - self.pump_ts).total_seconds()) > PEER_MAX_AGE_S:
            return None
        return self.pump_on


@dataclass
class _Ctx:
    events: list = field(default_factory=list)      # (tên sự kiện, payload): phát sau khi commit
    actions: list = field(default_factory=list)     # callable: chạy ở thread riêng sau khi commit


_state: dict[int, _DevState] = defaultdict(_DevState)
_sites: dict[int, _SiteState] = defaultdict(_SiteState)
_last_action: dict[tuple, float] = {}
_cfg_cache: dict[int, tuple] = {}
_rules_cache: dict[int, tuple] = {}
_peer_cache: dict[int, tuple] = {}


def reset_state() -> None:
    _state.clear()
    _sites.clear()
    _last_action.clear()
    _cfg_cache.clear()
    _rules_cache.clear()
    _peer_cache.clear()


def invalidate(device_id: int | None = None) -> None:
    """Gọi sau khi sửa luật, cấu hình hoặc site của thiết bị để engine đọc lại ngay."""
    if device_id is None:
        _cfg_cache.clear()
        _rules_cache.clear()
    else:
        _cfg_cache.pop(device_id, None)
        _rules_cache.pop(device_id, None)
    _peer_cache.clear()


def _site_key(dev: Device) -> int:
    return dev.site_id if dev.site_id is not None else -dev.id      # thiết bị chưa vào site: trạng thái riêng, không có node đối tác


# ----------------------------------------------------------------------------- luật
def ensure_default_rules(s: Session, dev: Device) -> None:
    have = set(s.scalars(select(AlertRule.type).where(AlertRule.device_id == dev.id)))
    for type_, d in RULES_BY_TYPE[dev.type].items():
        if type_ in have:
            continue
        try:
            with s.begin_nested():
                s.add(AlertRule(device_id=dev.id, type=type_, params_json=json.dumps(d["params"]),
                                severity=d["severity"], enabled=True))
        except IntegrityError:      # luồng khác vừa tạo
            pass


def load_rules(s: Session, dev: Device) -> dict[str, RuleView]:
    ensure_default_rules(s, dev)
    defaults = RULES_BY_TYPE[dev.type]
    out = {}
    for r in s.scalars(select(AlertRule).where(AlertRule.device_id == dev.id)):
        if r.type not in defaults:      # quy tắc không áp dụng cho loại node này (hoặc loại đã bỏ): bỏ qua
            continue
        base = defaults[r.type]["params"]
        try:
            stored = json.loads(r.params_json or "{}")
        except ValueError:
            stored = {}
        params = {**base, **{k: v for k, v in stored.items() if k in base}}
        out[r.type] = RuleView(r.id, r.type, bool(r.enabled), r.severity, params)
    return out


def _config(s: Session, device_id: int) -> dict:
    hit = _cfg_cache.get(device_id)
    if hit and time.monotonic() - hit[0] < _CACHE_TTL_S:
        return hit[1]
    cfg = device_params.get_config(s, device_id)
    _cfg_cache[device_id] = (time.monotonic(), cfg)
    return cfg


def _context(s: Session, dev: Device):
    hit = _rules_cache.get(dev.id)
    if hit and time.monotonic() - hit[0] < _CACHE_TTL_S:
        rules = hit[1]
    else:
        rules = load_rules(s, dev)
        _rules_cache[dev.id] = (time.monotonic(), rules)
    return _config(s, dev.id), rules


def _peers(s: Session, dev: Device) -> dict[str, _Peer]:
    """Các node trong cùng site, theo loại ('tank', 'pipe'); gồm cả chính thiết bị này. Rỗng nếu chưa vào site."""
    if dev.site_id is None:
        return {}
    hit = _peer_cache.get(dev.site_id)
    if hit and time.monotonic() - hit[0] < _CACHE_TTL_S:
        return hit[1]
    peers: dict[str, _Peer] = {}
    for d in s.scalars(select(Device).where(Device.site_id == dev.site_id, Device.state != "Decommissioned")
                       .order_by(Device.id)):
        peers.setdefault(d.type, _Peer(d.id, d.device_code, d.type))
    _peer_cache[dev.site_id] = (time.monotonic(), peers)
    return peers


def _clean_params(type_: str, dev_type: str, params: dict) -> dict:
    allowed = RULES_BY_TYPE[dev_type][type_]["params"]
    out = {}
    for k, v in params.items():
        if k not in allowed:
            raise InvalidInput(f"{type_}: tham số '{k}' không hợp lệ cho node {dev_type}")
        lo, hi = PARAM_BOUNDS[k]
        if not (lo <= v <= hi):
            raise InvalidInput(f"{type_}.{k} phải trong khoảng {lo}..{hi}")
        out[k] = int(v) if float(v).is_integer() else float(v)
    return out


def apply_rule_updates(s: Session, dev: Device, updates: list[dict], *, actor_id: int, ip: str) -> dict[str, RuleView]:
    seen = [u["type"] for u in updates]
    if len(set(seen)) != len(seen):
        raise InvalidInput("Mỗi loại quy tắc chỉ được nêu một lần")
    for type_ in seen:
        if type_ not in RULES_BY_TYPE[dev.type]:
            raise InvalidInput(f"Quy tắc {type_} không áp dụng cho node {dev.type}")
    ensure_default_rules(s, dev)
    s.flush()
    rows = {r.type: r for r in s.scalars(select(AlertRule).where(AlertRule.device_id == dev.id))}
    changes = []
    for u in updates:
        row = rows[u["type"]]
        if u.get("severity") is not None:
            if u["severity"] not in SEVERITIES:
                raise InvalidInput("severity phải là warning hoặc critical")
            row.severity = u["severity"]
            changes.append(f"{u['type']} severity={u['severity']}")
        if u.get("enabled") is not None:
            row.enabled = bool(u["enabled"])
            changes.append(f"{u['type']} enabled={row.enabled}")
        if u.get("params"):
            clean = _clean_params(u["type"], dev.type, u["params"])
            row.params_json = json.dumps({**json.loads(row.params_json or "{}"), **clean})
            changes.append(f"{u['type']} params={clean}")
    write_audit(s, actor_id, "alert_rule.update", "device", dev.id, ip, "; ".join(changes))
    s.commit()
    invalidate(dev.id)
    return load_rules(s, dev)


# ----------------------------------------------------------------------------- sinh / đóng cảnh báo
def _iso(dt: datetime | None) -> str | None:
    return None if dt is None else dt.strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def alert_event(a: Alert, dev: Device) -> dict:
    return {"alert_id": a.id, "device_id": dev.id, "device_code": dev.device_code, "device_type": dev.type,
            "site_id": dev.site_id, "type": a.type, "severity": a.severity, "value": a.value, "state": a.state,
            "opened_at": _iso(a.opened_at), "acked_at": _iso(a.acked_at), "closed_at": _iso(a.closed_at)}


def _raise(s: Session, ctx: _Ctx, dev: Device, rule: RuleView, value: float, ts: datetime) -> Alert | None:
    """Mở cảnh báo nếu chưa có cảnh báo đang mở cùng loại và đã qua cooldown. Trả None nếu bị chặn."""
    active = s.scalars(select(Alert.id).where(Alert.device_id == dev.id, Alert.type == rule.type,
                                              Alert.state.in_(("open", "ack")))).first()
    if active:
        return None
    last_closed = s.scalars(select(Alert.closed_at).where(Alert.device_id == dev.id, Alert.type == rule.type,
                                                          Alert.state == "closed")
                            .order_by(Alert.closed_at.desc()).limit(1)).first()
    if last_closed and (ts - last_closed).total_seconds() < rule.params.get("cooldown_s", 300):
        return None
    a = Alert(device_id=dev.id, rule_id=rule.id, type=rule.type, severity=rule.severity,
              value=float(value), state="open", opened_at=ts)
    s.add(a)
    s.flush()
    write_audit(s, None, "alert.open", "alert", a.id, "system",
                f"device={dev.device_code} type={rule.type} value={float(value):.2f}")
    ctx.events.append(("alert", alert_event(a, dev)))
    return a


def _clear(s: Session, ctx: _Ctx, dev: Device, type_: str, ts: datetime) -> None:
    for a in s.scalars(select(Alert).where(Alert.device_id == dev.id, Alert.type == type_,
                                           Alert.state.in_(("open", "ack")))).all():
        a.state, a.closed_at = "closed", ts
        s.flush()
        write_audit(s, None, "alert.auto_close", "alert", a.id, "system", f"device={dev.device_code} type={type_}")
        ctx.events.append(("alert", alert_event(a, dev)))


# ----------------------------------------------------------------------------- hành động
def _throttled(device_id: int, name: str) -> bool:
    now, key = time.monotonic(), (device_id, name)
    if now - _last_action.get(key, -1e9) < SAFETY_THROTTLE_S:
        return True
    _last_action[key] = now
    return False


def _pump_action(pump_device_id: int, value: str, duration_s: int | None, source: str):
    """Lệnh bơm tự động. Luôn gửi tới node ỐNG (thiết bị điều khiển bơm); duration_s=None thì lệnh bật lấy
    thời lượng mặc định theo cấu hình pump_max_run_s của node ống."""
    def run():
        publisher = _publisher
        if publisher is None:
            log.warning("không có publisher, bỏ qua %s device=%s", source, pump_device_id)
            return
        try:
            with session_scope() as s:
                dev = s.get(Device, pump_device_id)
                if dev is not None:
                    commands.send_pump_command(s, publisher, dev, value=value, duration_s=duration_s,
                                               actor_id=None, ip="system", source=source)
        except (Conflict, InvalidInput, PublishError) as e:
            log.warning("lệnh tự động %s bị từ chối device=%s: %s", source, pump_device_id, e)
        except Exception:
            log.exception("lỗi lệnh tự động %s device=%s", source, pump_device_id)
    return run


def _set_fault(s: Session, ctx: _Ctx, dev: Device, reason: str) -> None:
    if dev.state != "Active":
        return
    dev.state = "Fault"
    write_audit(s, None, "device.state", "device", dev.id, "system", f"Active->Fault ({reason})")
    ctx.events.append(("device_state", {"device_code": dev.device_code, "device_id": dev.id, "type": dev.type,
                                        "site_id": dev.site_id, "state": "Fault", "online": dev.online,
                                        "fw_version": dev.fw_version}))


# ----------------------------------------------------------------------------- quy tắc của node bồn (mực nước)
def _rule_low(s, ctx, dev, rule, cfg, st: _DevState, site: _SiteState, peers, smp: Sample, fresh: bool) -> None:
    if rule is None or not rule.enabled:
        return
    p, low = rule.params, float(cfg["low_pct"])
    if smp.level_pct < low:
        st.low_since = st.low_since or smp.ts
        if (smp.ts - st.low_since).total_seconds() >= p["min_duration_s"]:
            alert = _raise(s, ctx, dev, rule, smp.level_pct, smp.ts)
            if alert and cfg["auto_mode"] and fresh and dev.state == "Active":
                pipe = peers.get("pipe")
                if pipe is None:
                    log.warning("LOW_LEVEL device=%s: site chưa có node ống, không thể tự bật bơm", dev.device_code)
                elif site.pump_at(smp.ts) is not True:          # bơm đang chạy rồi thì không cần bật lại
                    ctx.actions.append(_pump_action(pipe.id, "on", None, "auto:LOW_LEVEL"))
    else:
        st.low_since = None
        if smp.level_pct > low + p["hysteresis_pct"]:
            _clear(s, ctx, dev, "LOW_LEVEL", smp.ts)


def _rule_high(s, ctx, dev, rule, cfg, st: _DevState, site: _SiteState, peers, smp: Sample, fresh: bool) -> None:
    if rule is None or not rule.enabled:
        return
    p, high = rule.params, float(cfg["high_pct"])
    if smp.level_pct > high:
        st.high_since = st.high_since or smp.ts
        if (smp.ts - st.high_since).total_seconds() >= p["min_duration_s"]:
            _raise(s, ctx, dev, rule, smp.level_pct, smp.ts)
            # Ngắt bơm là hành động bảo vệ: không phụ thuộc cảnh báo có bị cooldown chặn hay không. Gửi khi bơm đang
            # chạy HOẶC không biết trạng thái bơm (an toàn hơn là bỏ qua); chỉ bỏ qua khi biết chắc bơm đã tắt.
            pipe = peers.get("pipe")
            if (pipe is not None and fresh and site.pump_at(smp.ts) is not False
                    and not _throttled(pipe.id, "high_off")):
                ctx.actions.append(_pump_action(pipe.id, "off", None, "auto:HIGH_LEVEL"))
    else:
        st.high_since = None
        if smp.level_pct < high - p["hysteresis_pct"]:
            _clear(s, ctx, dev, "HIGH_LEVEL", smp.ts)


def _drop_rate_cm_per_min(win, tank_height_cm: float) -> float | None:
    """Tốc độ giảm mực (cm/phút, dương = đang giảm) từ trung vị nhóm mẫu đầu và nhóm mẫu cuối của cửa sổ."""
    n = len(win)
    k = max(3, min(5, n // 4))
    if n < 2 * k:
        return None
    pts = list(win)
    first, last = pts[:k], pts[-k:]
    minutes = (last[k // 2][0] - first[k // 2][0]).total_seconds() / 60
    if minutes <= 0:
        return None
    drop_pct = statistics.median(v for _, v in first) - statistics.median(v for _, v in last)
    return drop_pct / 100.0 * tank_height_cm / minutes


def _rule_leak_level(s, ctx, dev, rule, cfg, st: _DevState, site: _SiteState, peers, smp: Sample, fresh: bool) -> None:
    """Rò rỉ theo mực nước: mực giảm quá r cm/phút khi bơm tắt. Trạng thái bơm lấy từ node ống; không biết trạng
    thái bơm thì không kết luận (bơm có thể đang chạy)."""
    if rule is None or not rule.enabled:
        return
    p = rule.params
    if site.pump_at(smp.ts) is not False or site.pump_off_since is None:
        st.leak_win.clear()
        return
    if (smp.ts - site.pump_off_since).total_seconds() < p["settle_s"]:      # chờ mặt nước lắng sau khi tắt bơm
        return
    win = st.leak_win
    win.append((smp.ts, smp.level_pct))
    horizon = p["window_min"] * 60 + 2 * float(cfg["sample_interval_s"])
    while (smp.ts - win[0][0]).total_seconds() > horizon:
        win.popleft()
    if (win[-1][0] - win[0][0]).total_seconds() < p["window_min"] * 60:
        return
    rate = _drop_rate_cm_per_min(win, float(cfg["tank_height_cm"]))
    if rate is None:
        return
    if rate > p["rate_cm_per_min"]:
        _raise(s, ctx, dev, rule, rate, smp.ts)
    elif rate <= p["rate_cm_per_min"] / 2:      # hysteresis: "mực ổn định" = tốc độ giảm <= nửa ngưỡng
        _clear(s, ctx, dev, "LEAK_SUSPECT", smp.ts)


# ----------------------------------------------------------------------------- quy tắc của node ống (lưu lượng, bơm)
def _in_usage_hours(params: dict, ts: datetime) -> bool:
    start, end = int(params["usage_start_h"]), int(params["usage_end_h"])
    if start == end:                    # chưa cấu hình giờ dùng nước: luôn kiểm tra rò rỉ
        return False
    hour = (ts + timedelta(hours=float(params["utc_offset_h"]))).hour
    return start <= hour < end if start < end else (hour >= start or hour < end)


def _rule_leak_flow(s, ctx, dev, rule, cfg, st: _DevState, site: _SiteState, peers, smp: Sample, fresh: bool) -> None:
    """Rò rỉ theo lưu lượng: có dòng chảy >= leak_flow_lpm khi bơm tắt, liên tục quá leak_minutes, ngoài giờ dùng nước."""
    if rule is None or not rule.enabled:
        return
    p = rule.params
    leak_flow, need_s = float(cfg["leak_flow_lpm"]), int(cfg["leak_minutes"]) * 60
    if smp.pump_on or _in_usage_hours(p, smp.ts):       # đang bơm hoặc đang trong giờ dùng nước: dòng chảy là bình thường
        st.leak_since = st.leak_clear_since = None
        return
    if smp.flow_lpm >= leak_flow:
        st.leak_clear_since = None
        st.leak_since = st.leak_since or smp.ts
        if (smp.ts - st.leak_since).total_seconds() >= need_s:
            _raise(s, ctx, dev, rule, smp.flow_lpm, smp.ts)
    else:
        st.leak_since = None
        if smp.flow_lpm <= FLOW_EPS:                    # lưu lượng về 0 đủ lâu thì đóng
            st.leak_clear_since = st.leak_clear_since or smp.ts
            if (smp.ts - st.leak_clear_since).total_seconds() >= p["clear_s"]:
                _clear(s, ctx, dev, "LEAK_SUSPECT", smp.ts)
        else:
            st.leak_clear_since = None


def _rule_no_rise(s, ctx, dev, rule, cfg, st: _DevState, site: _SiteState, peers, smp: Sample, fresh: bool) -> None:
    """Bơm chạy quá T giây mà mực nước ở node bồn không tăng >= x%: ngắt bơm, node ống sang Fault."""
    if rule is None or not rule.enabled:
        return
    p = rule.params
    level = site.level_at(smp.ts)
    if not smp.pump_on or level is None:                # bơm tắt, hoặc không biết mực nước: không đủ cơ sở kết luận
        st.rise_since = st.rise_ref = None
        return
    if st.rise_since is None:
        st.rise_since, st.rise_ref = smp.ts, level
        return
    tank = peers.get("tank")
    high = float(_config(s, tank.id)["high_pct"]) if tank is not None else 90.0
    stagnant = ((smp.ts - st.rise_since).total_seconds() >= p["rise_window_s"]
                and level - st.rise_ref < p["min_rise_pct"] and level < high)
    if not stagnant:
        return
    _raise(s, ctx, dev, rule, level - st.rise_ref, smp.ts)
    # Bảo vệ: ngắt bơm và chuyển Fault (chỉ khi mẫu còn mới và thiết bị đang Active, nên chỉ làm một lần)
    if fresh and dev.state == "Active":
        _set_fault(s, ctx, dev, "PUMP_NO_RISE")
        ctx.actions.append(_pump_action(dev.id, "off", None, "auto:PUMP_NO_RISE"))


TANK_RULES = (("LOW_LEVEL", _rule_low), ("HIGH_LEVEL", _rule_high), ("LEAK_SUSPECT", _rule_leak_level))
PIPE_RULES = (("LEAK_SUSPECT", _rule_leak_flow), ("PUMP_NO_RISE", _rule_no_rise))


def _evaluate(s: Session, ctx: _Ctx, smp: Sample) -> None:
    dev = s.get(Device, smp.device_id)
    if dev is None or dev.state not in ("Active", "Fault"):
        return
    st = _state[dev.id]
    if st.last_ts is not None:
        if smp.ts <= st.last_ts:                # mẫu cũ/đảo thứ tự: không dùng cho cửa sổ trạng thái
            return
        if (smp.ts - st.last_ts).total_seconds() > GAP_RESET_S:
            st.reset_windows()
    st.last_ts = smp.ts
    cfg, rules = _context(s, dev)
    fresh = (utcnow() - smp.ts).total_seconds() <= ACTION_MAX_AGE_S
    site, peers = _sites[_site_key(dev)], _peers(s, dev)
    if dev.type == "tank":
        if smp.level_pct is None:
            return
        site.set_level(smp.ts, smp.level_pct)
        chain = TANK_RULES
    else:
        if smp.flow_lpm is None or smp.pump_on is None:
            return
        site.set_pump(smp.ts, smp.pump_on)
        chain = PIPE_RULES
    for type_, fn in chain:
        fn(s, ctx, dev, rules.get(type_), cfg, st, site, peers, smp, fresh)


def _flush(ctx: _Ctx) -> None:
    for event, payload in ctx.events:
        emit(event, payload)
    for action in ctx.actions:
        _submit(action)


def evaluate(smp: Sample) -> None:
    """Gọi sau khi telemetry đã commit. Không ném lỗi ra ngoài để không làm hỏng luồng ingest."""
    ctx = _Ctx()
    try:
        with _engine_lock, session_scope() as s:
            _evaluate(s, ctx, smp)
    except Exception:
        log.exception("alert engine lỗi (device=%s)", smp.device_id)
        return
    _flush(ctx)


# ----------------------------------------------------------------------------- DEVICE_OFFLINE
def on_device_offline(device_id: int, ts: datetime | None = None) -> None:
    ts, ctx = ts or utcnow(), _Ctx()
    try:
        with _engine_lock, session_scope() as s:
            dev = s.get(Device, device_id)
            if dev is None:
                return
            _, rules = _context(s, dev)
            _state.pop(device_id, None)             # mất liên tục dữ liệu: bỏ mọi cửa sổ
            site = _sites.get(_site_key(dev))
            if site is not None:                    # dữ liệu của node này không còn đáng tin với node kia
                if dev.type == "tank":
                    site.level = site.level_ts = None
                else:
                    site.pump_on = site.pump_ts = site.pump_off_since = None
            rule = rules.get("DEVICE_OFFLINE")
            if rule and rule.enabled:
                silent = (ts - dev.last_seen).total_seconds() if dev.last_seen else 0.0
                _raise(s, ctx, dev, rule, max(silent, 0.0), ts)
    except Exception:
        log.exception("alert engine lỗi khi xử lý offline (device=%s)", device_id)
        return
    _flush(ctx)


def on_device_online(device_id: int, ts: datetime | None = None) -> None:
    ts, ctx = ts or utcnow(), _Ctx()
    try:
        with _engine_lock, session_scope() as s:
            dev = s.get(Device, device_id)
            if dev is not None:
                _clear(s, ctx, dev, "DEVICE_OFFLINE", ts)
    except Exception:
        log.exception("alert engine lỗi khi xử lý online (device=%s)", device_id)
        return
    _flush(ctx)
