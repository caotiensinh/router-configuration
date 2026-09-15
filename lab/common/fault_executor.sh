#!/usr/bin/env bash
set -Eeuo pipefail

NDH_ALLOW_FAULT_INJECTION="${NDH_ALLOW_FAULT_INJECTION:-0}"

ndh_fault_require_enabled() {
  if [[ "${NDH_ALLOW_FAULT_INJECTION}" != "1" ]]; then
    echo "fault injection is disabled; set NDH_ALLOW_FAULT_INJECTION=1 only for a disposable common lab" >&2
    return 40
  fi
  return 0
}

ndh_fault_require_common_topology() {
  ndh_fault_require_enabled || return $?
  ndh_init_names || return $?
  ndh_assert_standard_topology || return $?
}

ndh_fault_wan_primary_blackhole_active() {
  ndh_init_names || return $?
  sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" \
    tc qdisc show dev "${NDH_V_WAN_PRIMARY_NS}" | \
    grep -Eq 'qdisc netem .*loss 100%'
}

ndh_fault_inject_wan_primary_blackhole() {
  ndh_fault_require_common_topology || return $?
  ndh_require_command tc || return $?
  sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" \
    tc qdisc replace dev "${NDH_V_WAN_PRIMARY_NS}" root netem loss 100% || return $?
  ndh_fault_wan_primary_blackhole_active
}

ndh_fault_recover_wan_primary_blackhole() {
  ndh_fault_require_common_topology || return $?
  ndh_require_command tc || return $?
  sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" \
    tc qdisc del dev "${NDH_V_WAN_PRIMARY_NS}" root 2>/dev/null || true
  if ndh_fault_wan_primary_blackhole_active; then
    echo "WAN-primary blackhole remained active after recovery" >&2
    return 41
  fi
  return 0
}

ndh_fault_pid_in_namespace() {
  local namespace="$1"
  local pid="$2"
  [[ "${pid}" =~ ^[1-9][0-9]*$ ]] || return 1
  sudo ip netns pids "${namespace}" | grep -Fxq "${pid}"
}

ndh_fault_stop_namespace_process() {
  local namespace="$1"
  local pid="$2"

  ndh_fault_require_common_topology || return $?
  if ! ndh_fault_pid_in_namespace "${namespace}" "${pid}"; then
    echo "refusing to stop PID ${pid}: it is not owned by namespace ${namespace}" >&2
    return 42
  fi

  sudo kill "${pid}" || return $?
  for _attempt in $(seq 1 40); do
    if ! sudo kill -0 "${pid}" 2>/dev/null; then
      return 0
    fi
    sleep 0.05
  done
  echo "namespace process ${pid} did not stop" >&2
  return 43
}

ndh_fault_stop_primary_dns_responder() {
  local pid="$1"
  ndh_init_names || return $?
  ndh_fault_stop_namespace_process "${NDH_NS_WAN_PRIMARY}" "${pid}"
}

ndh_fault_assert_primary_dns_stopped() {
  local pid="$1"
  ndh_init_names || return $?
  if ndh_fault_pid_in_namespace "${NDH_NS_WAN_PRIMARY}" "${pid}"; then
    echo "primary DNS responder PID ${pid} is still present in the WAN-primary namespace" >&2
    return 44
  fi
  return 0
}
