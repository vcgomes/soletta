obj-$(FLOW_NODE_TYPE_BLUEZ) += bluez.mod
obj-bluez-$(FLOW_NODE_TYPE_BLUEZ) := bluez.json bluez.o flower-power.
obj-bluez-$(FLOW_NODE_TYPE_BLUEZ)-type := flow
obj-bluez-$(FLOW_NODE_TYPE_BLUEZ)-extra-cflags += $(SYSTEMD_CFLAGS) $(GLIB_CFLAGS)
obj-bluez-$(FLOW_NODE_TYPE_BLUEZ)-extra-ldflags += $(SYSTEMD_LDFLAGS) $(GLIB_LDFLAGS)
