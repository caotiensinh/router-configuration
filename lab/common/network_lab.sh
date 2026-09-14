#!/usr/bin/env bash
set -Eeuo pipefail

NDH_PREFIX="${NDH_PREFIX:-ndh}"

ndh_validate_prefix() {
  if [[ ! "${NDH_PREFIX}" =~ ^[A-Za-z0-9]+$ ]] || [[ ${#NDH_PREFIX} -gt 6 ]]; then
    echo "NDH_PREFIX must be alphanumeric and at most 6 characters" >&2
    return 2
  fi
}

ndh_init_names() {
  ndh_validate_prefix
  NDH_NS_WAN_PRIMARY="${NDH_PREFIX}-wp"
  NDH_NS_WAN_BACKUP="${NDH_PREFIX}-wb"
  NDH_NS_LAN="${NDH_PREFIX}-lan"

  NDH_BR_WAN_PRIMARY="br-${NDH_PREFIX}-wp"
  NDH_BR_WAN_BACKUP="br-${NDH_PREFIX}-wb"
  NDH_BR_LAN="br-${NDH_PREFIX}-lan"

  NDH_TAP_WAN_PRIMARY="tap-${NDH_PREFIX}-wp"
  NDH_TAP_WAN_BACKUP="tap-${NDH_PREFIX}-wb"
  NDH_TAP_LAN="tap-${NDH_PREFIX}-lan"

  NDH_V_WAN_PRIMARY_BR="v-${NDH_PREFIX}-wp-b"
  NDH_V_WAN_PRIMARY_NS="v-${NDH_PREFIX}-wp-n"
  NDH_V_WAN_BACKUP_BR="v-${NDH_PREFIX}-wb-b"
  NDH_V_WAN_BACKUP_NS="v-${NDH_PREFIX}-wb-n"
  NDH_V_LAN_BR="v-${NDH_PREFIX}-lan-b"
  NDH_V_LAN_NS="v-${NDH_PREFIX}-lan-n"
}

ndh_require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    return 2
  }
}

ndh_create_bridge_with_tap() {
  local bridge="$1"
  local tap="$2"
  sudo ip link add name "${bridge}" type bridge
  sudo ip link set "${bridge}" up
  sudo ip tuntap add dev "${tap}" mode tap user "$(id -un)"
  sudo ip link set "${tap}" master "${bridge}"
  sudo ip link set "${tap}" up
}

ndh_create_veth_into_ns() {
  local bridge="$1"
  local host_if="$2"
  local ns_if="$3"
  local ns="$4"
  sudo ip netns add "${ns}"
  sudo ip link add "${host_if}" type veth peer name "${ns_if}"
  sudo ip link set "${host_if}" master "${bridge}"
  sudo ip link set "${host_if}" up
  sudo ip link set "${ns_if}" netns "${ns}"
  sudo ip netns exec "${ns}" ip link set lo up
  sudo ip netns exec "${ns}" ip link set "${ns_if}" up
}

ndh_cleanup_standard_topology() {
  ndh_init_names
  for ns in "${NDH_NS_LAN}" "${NDH_NS_WAN_BACKUP}" "${NDH_NS_WAN_PRIMARY}"; do
    sudo ip netns del "${ns}" 2>/dev/null || true
  done
  for tap in "${NDH_TAP_LAN}" "${NDH_TAP_WAN_BACKUP}" "${NDH_TAP_WAN_PRIMARY}"; do
    sudo ip link del "${tap}" 2>/dev/null || true
  done
  for bridge in "${NDH_BR_LAN}" "${NDH_BR_WAN_BACKUP}" "${NDH_BR_WAN_PRIMARY}"; do
    sudo ip link del "${bridge}" 2>/dev/null || true
  done
}

ndh_setup_standard_topology() {
  ndh_init_names
  for command in ip sudo; do
    ndh_require_command "${command}"
  done

  ndh_cleanup_standard_topology

  ndh_create_bridge_with_tap "${NDH_BR_WAN_PRIMARY}" "${NDH_TAP_WAN_PRIMARY}"
  ndh_create_bridge_with_tap "${NDH_BR_WAN_BACKUP}" "${NDH_TAP_WAN_BACKUP}"
  ndh_create_bridge_with_tap "${NDH_BR_LAN}" "${NDH_TAP_LAN}"

  ndh_create_veth_into_ns \
    "${NDH_BR_WAN_PRIMARY}" "${NDH_V_WAN_PRIMARY_BR}" "${NDH_V_WAN_PRIMARY_NS}" "${NDH_NS_WAN_PRIMARY}"
  ndh_create_veth_into_ns \
    "${NDH_BR_WAN_BACKUP}" "${NDH_V_WAN_BACKUP_BR}" "${NDH_V_WAN_BACKUP_NS}" "${NDH_NS_WAN_BACKUP}"
  ndh_create_veth_into_ns \
    "${NDH_BR_LAN}" "${NDH_V_LAN_BR}" "${NDH_V_LAN_NS}" "${NDH_NS_LAN}"

  sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" ip addr add 192.0.2.1/30 dev "${NDH_V_WAN_PRIMARY_NS}"
  sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" ip addr add 203.0.113.100/32 dev lo
  sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" ip addr add 203.0.113.53/32 dev lo
  sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" ip route add 10.10.10.0/24 via 192.0.2.2 dev "${NDH_V_WAN_PRIMARY_NS}"

  sudo ip netns exec "${NDH_NS_WAN_BACKUP}" ip addr add 198.51.100.1/30 dev "${NDH_V_WAN_BACKUP_NS}"
  sudo ip netns exec "${NDH_NS_WAN_BACKUP}" ip addr add 203.0.113.100/32 dev lo
  sudo ip netns exec "${NDH_NS_WAN_BACKUP}" ip addr add 203.0.113.53/32 dev lo
  sudo ip netns exec "${NDH_NS_WAN_BACKUP}" ip route add 10.10.10.0/24 via 198.51.100.2 dev "${NDH_V_WAN_BACKUP_NS}"

  sudo ip netns exec "${NDH_NS_LAN}" ip addr add 10.10.10.2/24 dev "${NDH_V_LAN_NS}"
  sudo ip netns exec "${NDH_NS_LAN}" ip route add default via 10.10.10.1 dev "${NDH_V_LAN_NS}"
}

ndh_assert_standard_topology() {
  ndh_init_names
  for bridge in "${NDH_BR_WAN_PRIMARY}" "${NDH_BR_WAN_BACKUP}" "${NDH_BR_LAN}"; do
    ip link show "${bridge}" >/dev/null
  done
  for tap in "${NDH_TAP_WAN_PRIMARY}" "${NDH_TAP_WAN_BACKUP}" "${NDH_TAP_LAN}"; do
    ip link show "${tap}" >/dev/null
  done
  sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" ip -4 addr show dev "${NDH_V_WAN_PRIMARY_NS}" | grep -Fq "192.0.2.1/30"
  sudo ip netns exec "${NDH_NS_WAN_BACKUP}" ip -4 addr show dev "${NDH_V_WAN_BACKUP_NS}" | grep -Fq "198.51.100.1/30"
  sudo ip netns exec "${NDH_NS_LAN}" ip -4 addr show dev "${NDH_V_LAN_NS}" | grep -Fq "10.10.10.2/24"
  sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" ip -4 addr show dev lo | grep -Fq "203.0.113.100"
  sudo ip netns exec "${NDH_NS_WAN_PRIMARY}" ip -4 addr show dev lo | grep -Fq "203.0.113.53"
  sudo ip netns exec "${NDH_NS_WAN_BACKUP}" ip -4 addr show dev lo | grep -Fq "203.0.113.100"
  sudo ip netns exec "${NDH_NS_WAN_BACKUP}" ip -4 addr show dev lo | grep -Fq "203.0.113.53"
}

ndh_print_attachment_env() {
  ndh_init_names
  cat <<EOF
NDH_TAP_WAN_PRIMARY=${NDH_TAP_WAN_PRIMARY}
NDH_TAP_WAN_BACKUP=${NDH_TAP_WAN_BACKUP}
NDH_TAP_LAN=${NDH_TAP_LAN}
NDH_NS_WAN_PRIMARY=${NDH_NS_WAN_PRIMARY}
NDH_NS_WAN_BACKUP=${NDH_NS_WAN_BACKUP}
NDH_NS_LAN=${NDH_NS_LAN}
EOF
}
