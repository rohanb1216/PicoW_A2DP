#include "bt.h"

#include "sdp.h"
#include "a2dp.h"
#include "avrcp.h"

#include <hci.h>
#include "l2cap.h"
#include <btstack_event.h>
#include <btstack_run_loop.h>
#include <stdio.h>

#include <memory.h>
#include <btstack_tlv.h>

static char device_addr_string[] = "00:00:00:00:00:00";
static bool _is_up = false;
static bd_addr_t _local_addr = {0};
static bt_on_up_cb_t _cb = 0;
static void *_data = 0;
static const char *_name = 0;
static const char *_pin = 0;
static const uint32_t tag = 7103332;  //Last Connected Device - lcd
static btstack_packet_callback_registration_t _hci_registration;

typedef struct {
    const btstack_tlv_t * btstack_tlv_impl;
    void * btstack_tlv_context;
} btstack_link_key_db_tlv_h;

typedef struct {
    bd_addr_t addr;
    bd_addr_type_t addr_type;
} le_device_addr_t;

static btstack_link_key_db_tlv_h singleton;
static btstack_link_key_db_tlv_h * self = &singleton;

static le_device_addr_t remote_device;

#ifdef HAVE_BTSTACK_STDIN
static void stdin_process(char cmd);
#endif

static void packet_handler(uint8_t packet_type, uint16_t channel, uint8_t *packet, uint16_t size)
{
    UNUSED(size);
    UNUSED(channel);

    bd_addr_t address;
    uint16_t cid;
    // const btstack_tlv_t *tlv;
    // const void *tlv_context;


    if (packet_type != HCI_EVENT_PACKET)
        return;

    switch (hci_event_packet_get_type(packet))
    {

    case BTSTACK_EVENT_STATE:
        if (btstack_event_state_get_state(packet) != HCI_STATE_WORKING)
            return;
        gap_local_bd_addr(_local_addr);
        _is_up = true;
        if (_cb)
            (*_cb)(_data);
        printf("Working");
        btstack_tlv_get_instance(&self->btstack_tlv_impl, &self->btstack_tlv_context);
        self->btstack_tlv_impl->get_tag(self->btstack_tlv_context, tag, (uint8_t*) &address, sizeof(address));
        self->btstack_tlv_impl->delete_tag(self->btstack_tlv_context, tag);
        a2dp_sink_establish_stream(address,&cid);
        break;

    case HCI_EVENT_PIN_CODE_REQUEST:
        hci_event_pin_code_request_get_bd_addr(packet, address);
        gap_pin_code_response(address, _pin);
        break;

    case HCI_EVENT_CONNECTION_COMPLETE:
            hci_event_connection_complete_get_bd_addr(packet, address);
            // tlv.store_tag(packet, tag, address, sizeof(address));
            btstack_tlv_get_instance(&self->btstack_tlv_impl, &self->btstack_tlv_context);
            self->btstack_tlv_impl->store_tag(self->btstack_tlv_context, tag, (uint8_t*) &address, sizeof(address));
            break;
    case HCI_EVENT_DISCONNECTION_COMPLETE:
            btstack_tlv_get_instance(&self->btstack_tlv_impl, &self->btstack_tlv_context);
            self->btstack_tlv_impl->delete_tag(self->btstack_tlv_context, tag);


    default:
        break;
    }
}

void bt_begin(const char *name, const char *pin, bt_on_up_cb_t cb, void *data)
{
    _name = name ? name : "Pico 00:00:00:00:00:00";
    _pin = pin ? pin : "0000";
    _data = data;
    _cb = cb;

    l2cap_init();
    sdp_begin();

    a2dp_sink_begin();
    avrcp_begin();

    gap_set_local_name(_name);
    gap_discoverable_control(1);
    gap_set_class_of_device(0x200414); // Service Class: Audio, Major Device Class: Audio, Minor: Loudspeaker
    gap_set_default_link_policy_settings(LM_LINK_POLICY_ENABLE_ROLE_SWITCH | LM_LINK_POLICY_ENABLE_SNIFF_MODE);
    gap_set_allow_role_switch(true); // A2DP Source, e.g. smartphone, can become master after re-connect.

    _hci_registration.callback = &packet_handler;
    hci_add_event_handler(&_hci_registration);

    get_link_keys();

#ifdef HAVE_BTSTACK_STDIN
    btstack_stdin_setup(stdin_process);
#endif
}

static void get_link_keys(void){
    bd_addr_t  addr;
    link_key_t link_key;
    link_key_type_t type;
    btstack_link_key_iterator_t it;

    int ok = gap_link_key_iterator_init(&it);
    if (!ok) {
        printf("Link key iterator not implemented\n");
        return;
    }
    printf("Stored link keys: \n");
    while (gap_link_key_iterator_get_next(&it, addr, link_key, &type)){
        printf("%s - type %u, key: ", bd_addr_to_str(addr), (int) type);
        printf_hexdump(link_key, 16);
    }
    printf(".\n");
    gap_link_key_iterator_done(&it);
}

static void get_last_connected(void)
{
    bd_addr_t addr;
    self->btstack_tlv_impl->get_tag(self->btstack_tlv_context, tag, (uint8_t *) &addr, 6);
    printf("Last Device is %s\n", bd_addr_to_str(addr));
}

void bt_run()
{
    hci_power_control(HCI_POWER_ON);
    btstack_run_loop_execute();
}

bool bt_up()
{
    return _is_up;
}

static void stdin_process(char cmd)
{
    uint8_t status = ERROR_CODE_SUCCESS;
    switch (cmd)
    {
    case 'p':
        get_link_keys();
        break;
    case 'l':
        get_last_connected();
        break;
    default:
        break;
    }
}

void bt_addr(bd_addr_t local_addr)
{
    memcpy(local_addr, _local_addr, sizeof(bd_addr_t));
}
