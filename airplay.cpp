#include "airplay.hpp"
#include <chrono>
#include <log/log.hpp>
#include <obs/obs.h>

#include <assert.h>
#include <cstring>
#include <fstream>
#include <signal.h>
#include <stddef.h>
#include <string>
#include <sys/utsname.h>
#include <unistd.h>
#include <vector>

#include <ifaddrs.h>
#include <sys/socket.h>
#ifdef __linux__
#include <netpacket/packet.h>
#else
#include <net/if_dl.h>
#endif

#include "dnssd.h"
#include "logger.h"
#include "raop.h"
#include "stream.h"

#define DEFAULT_NAME "OBS"
#define DEFAULT_DEBUG_LOG false
#define NTP_TIMEOUT_LIMIT 5
#define LOWEST_ALLOWED_PORT 1024
#define HIGHEST_PORT 65535
#define LOGE LOG

static std::string server_name = DEFAULT_NAME;
static unsigned int max_ntp_timeouts = NTP_TIMEOUT_LIMIT;

static int  audiodelay = -1;
static dnssd_t *dnssd = NULL;
static int max_connections = 2;
static unsigned short display[5] = {0}, tcp[3] = {0}, udp[3] = {0};
static bool require_password = false;
static unsigned short pin = 3050;
static std::string keyfile = "";
static std::string mac_address = "";
static std::string dacpfile = "";
static unsigned short raop_port;
static unsigned short airplay_port;
static bool show_client_FPS_data = false;

static bool setup_legacy_pairing = false;


static std::string find_mac()
{
  /*  finds the MAC address of a network interface *
   *  in a Linux, *BSD or macOS system.            */
  std::string mac = "";
  struct ifaddrs *ifap, *ifaptr;
  int non_null_octets = 0;
  unsigned char octet[6];
  if (getifaddrs(&ifap) == 0)
  {
    for (ifaptr = ifap; ifaptr != NULL; ifaptr = ifaptr->ifa_next)
    {
      if (ifaptr->ifa_addr == NULL)
        continue;
#ifdef __linux__
      if (ifaptr->ifa_addr->sa_family != AF_PACKET)
        continue;
      struct sockaddr_ll *s = (struct sockaddr_ll *)ifaptr->ifa_addr;
      for (int i = 0; i < 6; i++)
      {
        if ((octet[i] = s->sll_addr[i]) != 0)
          non_null_octets++;
      }
#else /* macOS and *BSD */
      if (ifaptr->ifa_addr->sa_family != AF_LINK)
        continue;
      ptr = (unsigned char *)LLADDR((struct sockaddr_dl *)ifaptr->ifa_addr);
      for (int i = 0; i < 6; i++)
      {
        if ((octet[i] = *ptr) != 0)
          non_null_octets++;
        ptr++;
      }
#endif
      if (non_null_octets)
      {
        mac.erase();
        char str[3];
        for (int i = 0; i < 6; i++)
        {
          sprintf(str, "%02x", octet[i]);
          mac = mac + str;
          if (i < 5)
            mac = mac + ":";
        }
        break;
      }
    }
  }
  freeifaddrs(ifap);
  return mac;
}

#define MULTICAST 0
#define LOCAL 1
#define OCTETS 6
static std::string random_mac()
{
  char str[3];
  int octet = rand() % 64;
  octet = (octet << 1) + LOCAL;
  octet = (octet << 1) + MULTICAST;
  snprintf(str, 3, "%02x", octet);
  std::string mac_address(str);
  for (int i = 1; i < OCTETS; i++)
  {
    mac_address = mac_address + ":";
    octet = rand() % 256;
    snprintf(str, 3, "%02x", octet);
    mac_address = mac_address + str;
  }
  return mac_address;
}

static int parse_hw_addr(std::string str, std::vector<char> &hw_addr)
{
  for (auto i = 0U; i < str.length(); i += 3)
  {
    hw_addr.push_back((char)stol(str.substr(i), NULL, 16));
  }
  return 0;
}

auto AirPlay::stop_raop_server() -> int
{
  LOG("Stopping raop service");
  if (raop)
  {
    raop_destroy(raop);
    raop = NULL;
  }
  if (dnssd)
  {
    LOG("Stopping DNSSD");
    dnssd_unregister_raop(dnssd);
    dnssd_unregister_airplay(dnssd);
    dnssd_destroy(dnssd);
    dnssd = NULL;
  }
  return 0;
}

auto AirPlay::start_raop_server(std::vector<char> hw_addr,
                                unsigned short tcp[3],
                                unsigned short udp[3],
                                bool debug_log) -> int
{
  raop_callbacks_t raop_cbs;
  memset(&raop_cbs, 0, sizeof(raop_cbs));
  raop_cbs.conn_init = conn_init;
  raop_cbs.conn_destroy = conn_destroy;
  raop_cbs.conn_reset = conn_reset;
  raop_cbs.conn_teardown = conn_teardown;
  raop_cbs.audio_process = audio_process;
  raop_cbs.video_process = video_process;
  raop_cbs.audio_flush = audio_flush;
  raop_cbs.video_flush = video_flush;
  raop_cbs.video_pause = video_pause;
  raop_cbs.video_resume = video_resume;
  raop_cbs.audio_set_volume = audio_set_volume;
  raop_cbs.audio_get_format = audio_get_format;
  raop_cbs.video_report_size = video_report_size;
  raop_cbs.audio_set_metadata = audio_set_metadata;
  raop_cbs.audio_set_coverart = audio_set_coverart;
  raop_cbs.audio_set_progress = audio_set_progress;
  raop_cbs.report_client_request = report_client_request;
  raop_cbs.display_pin = display_pin;
  raop_cbs.register_client = register_client;
  raop_cbs.check_register = check_register;
  raop_cbs.export_dacp = export_dacp;

  raop = raop_init(&raop_cbs);
  if (raop == NULL) {
      LOGE("Error initializing raop!");
      return -1;
  }
  raop_set_log_callback(raop, log_callback, NULL);
  raop_set_log_level(raop, debug_log ? LOGGER_DEBUG : LOGGER_INFO);
  /* set max number of connections = 2 to protect against capture by new client */
  if (raop_init2(raop, max_connections, mac_address.c_str(), keyfile.c_str())){
      LOGE("Error initializing raop (2)!");
      free (raop);
      return -1;
  }

  /* write desired display pixel width, pixel height, refresh_rate, max_fps, overscanned.  */
  /* use 0 for default values 1920,1080,60,30,0; these are sent to the Airplay client      */

  if (display[0]) raop_set_plist(raop, "width", (int) display[0]);
  if (display[1]) raop_set_plist(raop, "height", (int) display[1]);
  if (display[2]) raop_set_plist(raop, "refreshRate", (int) display[2]);
  if (display[3]) raop_set_plist(raop, "maxFPS", (int) display[3]);
  if (display[4]) raop_set_plist(raop, "overscanned", (int) display[4]);

  if (show_client_FPS_data) raop_set_plist(raop, "clientFPSdata", 1);
  raop_set_plist(raop, "max_ntp_timeouts", max_ntp_timeouts);
  if (audiodelay >= 0) raop_set_plist(raop, "audio_delay_micros", audiodelay);
  if (require_password) raop_set_plist(raop, "pin", (int) pin);

  /* network port selection (ports listed as "0" will be dynamically assigned) */
  raop_set_tcp_ports(raop, tcp);
  raop_set_udp_ports(raop, udp);

  raop_port = raop_get_port(raop);
  raop_start(raop, &raop_port);
  raop_set_port(raop, raop_port);

  if (tcp[2]) {
      airplay_port = tcp[2];
  } else {
      /* is there a problem if this coincides with a randomly-selected tcp raop_mirror_data port?
       * probably not, as the airplay port is only used for initial client contact */
      airplay_port = (raop_port != HIGHEST_PORT ? raop_port + 1 : raop_port - 1);
  }
  if (dnssd) {
      raop_set_dnssd(raop, dnssd);
  } else {
      LOGE("raop_set failed to set dnssd");
      return -2;
  }
  return 0;
}

// Server callbacks
auto AirPlay::conn_init(void *cls) -> void
{
  LOG(__func__);

  auto self = static_cast<AirPlay *>(cls);
  self->open_connections++;
  self->connections_stopped = false;
  LOG("Open connections:", self->open_connections);
}

auto AirPlay::conn_destroy(void *cls) -> void
{
  LOG(__func__);
  auto self = static_cast<AirPlay *>(cls);
  // video_renderer_update_background(-1);
  self->open_connections--;
  LOG("Open connections:", self->open_connections);
  if (!self->open_connections)
  {
    self->connections_stopped = true;
  }
}

auto AirPlay::conn_reset(void *cls, int timeouts, bool reset_video) -> void
{
  auto self = static_cast<AirPlay *>(cls);
  LOG("***ERROR lost connection with client (network problem?)");
  if (timeouts)
  {
    LOG("   Client no-response limit of %d timeouts (%d seconds) reached:", timeouts, 3 * timeouts);
    LOG("   Sometimes the network connection may recover after a longer delay:\n"
        "   the default timeout limit n = %d can be changed with the \"-reset n\" option",
        NTP_TIMEOUT_LIMIT);
  }
  LOG("reset_video", reset_video);
  raop_stop(self->raop);
}

auto AirPlay::conn_teardown(void * /*cls*/, bool *teardown_96, bool *teardown_110) -> void
{
  LOG(__func__, *teardown_96, *teardown_110);
}

auto AirPlay::audio_process(void *cls, raop_ntp_t * /*ntp*/, audio_decode_struct *data) -> void
{
  auto self = static_cast<AirPlay *>(cls);
  self->render(data);
}

auto AirPlay::video_process(void *cls, raop_ntp_t * /*ntp*/, h264_decode_struct *data) -> void
{
  auto self = static_cast<AirPlay *>(cls);
  self->render(data);
}

auto AirPlay::audio_flush(void * /*cls*/) -> void
{
  LOG(__func__);
}

auto AirPlay::video_flush(void * /*cls*/) -> void
{
  LOG(__func__);
}

auto AirPlay::video_pause(void * /*cls*/) ->void
{
  LOG(__func__);
}

auto AirPlay::video_resume(void * /*cls*/) ->void
{
  LOG(__func__);
}

auto AirPlay::audio_set_volume(void * /*cls*/, float volume) -> void
{
  LOG(__func__, volume);
}

auto AirPlay::audio_set_coverart(void * /*cls*/, const void * /*buffer*/, int /*buflen*/) -> void
{
  LOG(__func__);
}

auto AirPlay::audio_set_progress(void * /*cls*/, unsigned int start, unsigned int curr, unsigned int end) -> void
{
  LOG(__func__, start, curr, end);
}

auto AirPlay::display_pin(void * /*cls*/, char * /*pin*/) -> void {
  LOG(__func__);
}

auto AirPlay::export_dacp(void * /*cls*/, const char * /*active_remote*/, const char * /*dacp_id*/) -> void {
  LOG(__func__);
}

auto AirPlay::register_client(void * /*cls*/, const char * /*device_id*/, const char * /*client_pk*/, const char *client_name) -> void {
  LOG(__func__, client_name);
}

auto AirPlay::check_register(void * /*cls*/, const char *client_pk) -> bool {
  LOG(__func__, client_pk);
  /* we are not maintaining a list of registered clients */
  return true;
}

auto AirPlay::report_client_request(void * /*cls*/, char *deviceid, char * model, char *name, bool * admit) -> void {
  LOG(__func__, deviceid, model, name, admit);
}

auto AirPlay::audio_get_format(void * /*cls*/,
                               unsigned char *ct,
                               unsigned short *spf,
                               bool *usingScreen,
                               bool *isMedia,
                               uint64_t *audioFormat) -> void
{
  unsigned char type;
  *ct = 1;
  LOG("ct=",
      static_cast<int>(*ct),
      "spf=",
      *spf,
      "usingScreen=",
      *usingScreen,
      "isMedia=",
      *isMedia,
      "audioFormat=",
      (unsigned long)*audioFormat);
  switch (*ct)
  {
  case 2: type = 0x20; break;
  case 8: type = 0x80; break;
  default: type = 0x10; break;
  }
  (void)type;
}

auto AirPlay::video_report_size(void *cls,
                                float *width_source,
                                float *height_source,
                                float *width,
                                float *height) -> void
{
  auto self = static_cast<AirPlay *>(cls);
  LOG("video_report_size:", *width_source, *height_source, *width, *height);
  self->width = *width_source;
  self->height = *height_source;
}

auto AirPlay::audio_set_metadata(void * /*cls*/, const void *buffer, int buflen) -> void
{
  LOG(__func__, buflen);
  unsigned char mark[] = {0x00, 0x00, 0x00}; /*daap seperator mark */
  if (buflen > 4)
  {
    LOG("==============Audio Metadata=============");
    const unsigned char *metadata = (const unsigned char *)buffer;
    const char *tag = (const char *)buffer;
    int len;
    metadata += 4;
    for (int i = 4; i < buflen; i++)
    {
      if (memcmp(metadata, mark, 3) == 0 && (len = (int)*(metadata + 3)))
      {
        bool found_text = true;
        if (strcmp(tag, "asal") == 0)
        {
          LOG("Album: ");
        }
        else if (strcmp(tag, "asar") == 0)
        {
          LOG("Artist: ");
        }
        else if (strcmp(tag, "ascp") == 0)
        {
          LOG("Composer: ");
        }
        else if (strcmp(tag, "asgn") == 0)
        {
          LOG("Genre: ");
        }
        else if (strcmp(tag, "minm") == 0)
        {
          LOG("Title: ");
        }
        else
        {
          found_text = false;
        }
        if (found_text)
        {
          const unsigned char *text = metadata + 4;
          for (int j = 0; j < len; j++)
          {
            LOG(*text);
            text++;
          }
        }
      }
      metadata++;
      tag++;
    }
  }
}

auto AirPlay::log_callback(void * /*cls*/, int level, const char *msg) -> void
{
  switch (level)
  {
  case LOGGER_DEBUG: {
    LOG("D", msg);
    break;
  }
  case LOGGER_WARNING: {
    LOG("W", msg);
    break;
  }
  case LOGGER_INFO: {
    LOG("I", msg);
    break;
  }
  case LOGGER_ERR: {
    LOG("E", msg);
    break;
  }
  default: break;
  }
}

static int start_dnssd(std::vector<char> hw_addr, std::string name) {
    int dnssd_error;
    int require_pw = (require_password ? 1 : 0);
    if (dnssd) {
        LOGE("start_dnssd error: dnssd != NULL");
        return 2;
    }
    dnssd = dnssd_init(name.c_str(), strlen(name.c_str()), hw_addr.data(), hw_addr.size(), &dnssd_error, require_pw);
    LOG("Started dnssd", dnssd_error, name, dnssd);
    if (dnssd_error) {
        LOGE("Could not initialize dnssd library!: error %d", dnssd_error);
        return 1;
    }
    /* after dnssd starts, reset the default feature set here
    /* (overwrites features set in dnssdint.h */
    /* default: FEATURES_1 = 0x5A7FFEE6, FEATURES_2 = 0 */

    dnssd_set_airplay_features(dnssd,  0, 0); // AirPlay video supported
    dnssd_set_airplay_features(dnssd,  1, 1); // photo supported
    dnssd_set_airplay_features(dnssd,  2, 1); // video protected with FairPlay DRM
    dnssd_set_airplay_features(dnssd,  3, 0); // volume control supported for videos

    dnssd_set_airplay_features(dnssd,  4, 0); // http live streaming (HLS) supported
    dnssd_set_airplay_features(dnssd,  5, 1); // slideshow supported
    dnssd_set_airplay_features(dnssd,  6, 1); //
    dnssd_set_airplay_features(dnssd,  7, 1); // mirroring supported

    dnssd_set_airplay_features(dnssd,  8, 0); // screen rotation  supported
    dnssd_set_airplay_features(dnssd,  9, 1); // audio supported
    dnssd_set_airplay_features(dnssd, 10, 1); //
    dnssd_set_airplay_features(dnssd, 11, 1); // audio packet redundancy supported

    dnssd_set_airplay_features(dnssd, 12, 1); // FaiPlay secure auth supported
    dnssd_set_airplay_features(dnssd, 13, 1); // photo preloading  supported
    dnssd_set_airplay_features(dnssd, 14, 1); // Authentication bit 4:  FairPlay authentication
    dnssd_set_airplay_features(dnssd, 15, 1); // Metadata bit 1 support:   Artwork

    dnssd_set_airplay_features(dnssd, 16, 1); // Metadata bit 2 support:  Soundtrack  Progress
    dnssd_set_airplay_features(dnssd, 17, 1); // Metadata bit 0 support:  Text (DAACP) "Now Playing" info.
    dnssd_set_airplay_features(dnssd, 18, 1); // Audio format 1 support:
    dnssd_set_airplay_features(dnssd, 19, 1); // Audio format 2 support: must be set for AirPlay 2 multiroom audio

    dnssd_set_airplay_features(dnssd, 20, 1); // Audio format 3 support: must be set for AirPlay 2 multiroom audio
    dnssd_set_airplay_features(dnssd, 21, 1); // Audio format 4 support:
    dnssd_set_airplay_features(dnssd, 22, 1); // Authentication type 4: FairPlay authentication
    dnssd_set_airplay_features(dnssd, 23, 0); // Authentication type 1: RSA Authentication

    dnssd_set_airplay_features(dnssd, 24, 0); //
    dnssd_set_airplay_features(dnssd, 25, 1); //
    dnssd_set_airplay_features(dnssd, 26, 0); // Has Unified Advertiser info
    dnssd_set_airplay_features(dnssd, 27, 1); // Supports Legacy Pairing

    dnssd_set_airplay_features(dnssd, 28, 1); //
    dnssd_set_airplay_features(dnssd, 29, 0); //
    dnssd_set_airplay_features(dnssd, 30, 1); // RAOP support: with this bit set, the AirTunes service is not required.
    dnssd_set_airplay_features(dnssd, 31, 0); //

    LOG("DNSSD Set Featues");
    for (int i = 32; i < 64; i++) {
        dnssd_set_airplay_features(dnssd, i, 0);
    }

    /*  bits 32-63 are  not used here: see  https://emanualcozzi.net/docs/airplay2/features
    dnssd_set_airplay_features(dnssd, 32, 0); // isCarPlay when ON,; Supports InitialVolume when OFF
    dnssd_set_airplay_features(dnssd, 33, 0); // Supports Air Play Video Play Queue
    dnssd_set_airplay_features(dnssd, 34, 0); // Supports Air Play from cloud (requires that bit 6 is ON)
    dnssd_set_airplay_features(dnssd, 35, 0); // Supports TLS_PSK

    dnssd_set_airplay_features(dnssd, 36, 0); //
    dnssd_set_airplay_features(dnssd, 37, 0); //
    dnssd_set_airplay_features(dnssd, 38, 0); //  Supports Unified Media Control (CoreUtils Pairing and Encryption)
    dnssd_set_airplay_features(dnssd, 39, 0); //

    dnssd_set_airplay_features(dnssd, 40, 0); // Supports Buffered Audio
    dnssd_set_airplay_features(dnssd, 41, 0); // Supports PTP
    dnssd_set_airplay_features(dnssd, 42, 0); // Supports Screen Multi Codec
    dnssd_set_airplay_features(dnssd, 43, 0); // Supports System Pairing

    dnssd_set_airplay_features(dnssd, 44, 0); // is AP Valeria Screen Sender
    dnssd_set_airplay_features(dnssd, 45, 0); //
    dnssd_set_airplay_features(dnssd, 46, 0); // Supports HomeKit Pairing and Access Control
    dnssd_set_airplay_features(dnssd, 47, 0); //

    dnssd_set_airplay_features(dnssd, 48, 0); // Supports CoreUtils Pairing and Encryption
    dnssd_set_airplay_features(dnssd, 49, 0); //
    dnssd_set_airplay_features(dnssd, 50, 0); // Metadata bit 3: "Now Playing" info sent by bplist not DAACP test
    dnssd_set_airplay_features(dnssd, 51, 0); // Supports Unified Pair Setup and MFi Authentication

    dnssd_set_airplay_features(dnssd, 52, 0); // Supports Set Peers Extended Message
    dnssd_set_airplay_features(dnssd, 53, 0); //
    dnssd_set_airplay_features(dnssd, 54, 0); // Supports AP Sync
    dnssd_set_airplay_features(dnssd, 55, 0); // Supports WoL

    dnssd_set_airplay_features(dnssd, 56, 0); // Supports Wol
    dnssd_set_airplay_features(dnssd, 57, 0); //
    dnssd_set_airplay_features(dnssd, 58, 0); // Supports Hangdog Remote Control
    dnssd_set_airplay_features(dnssd, 59, 0); // Supports AudioStreamConnection setup

    dnssd_set_airplay_features(dnssd, 60, 0); // Supports Audo Media Data Control
    dnssd_set_airplay_features(dnssd, 61, 0); // Supports RFC2198 redundancy
    */

    /* bit 27 of Features determines whether the AirPlay2 client-pairing protocol will be used (1) or not (0) */
    dnssd_set_airplay_features(dnssd, 27, (int) setup_legacy_pairing);
    return 0;
}


AirPlay::AirPlay(struct obs_data *obsData, struct obs_source *obsSource)
  : obsData(obsData),
    obsSource(obsSource),
    obsVFrame(std::make_unique<obs_source_frame>()),
    obsAFrame(std::make_unique<obs_source_audio>())
{
  std::vector<char> server_hw_addr;
  bool use_random_hw_addr = false;
  bool debug_log = DEFAULT_DEBUG_LOG;
  unsigned short tcp[3] = {0}, udp[3] = {0};

#ifdef SUPPRESS_AVAHI_COMPAT_WARNING
  // suppress avahi_compat nag message.  avahi emits a "nag" warning (once)
  // if  getenv("AVAHI_COMPAT_NOWARN") returns null.
  static char avahi_compat_nowarn[] = "AVAHI_COMPAT_NOWARN=1";
  if (!getenv("AVAHI_COMPAT_NOWARN"))
    putenv(avahi_compat_nowarn);
#endif

  /* may need a keyfile */

  if (udp[0])
    LOG("using network ports UDP", udp[0], udp[1], udp[2], "TCP", tcp[0], tcp[1], tcp[2]);

  std::string mac_address;
  if (!use_random_hw_addr)
    mac_address = find_mac();
  if (mac_address.empty())
  {
    srand(time(NULL) * getpid());
    mac_address = random_mac();
    LOG("using randomly-generated MAC address", mac_address);
  }
  else
  {
    LOG("using system MAC address", mac_address);
  }
  parse_hw_addr(mac_address, server_hw_addr);

  connections_stopped = true;

  LOG("Starting dnssd", server_name.c_str());
  if (start_dnssd(server_hw_addr, server_name)) {
    LOG("start_dnssd failed");
    return;
  }

  LOG("DNSSD: %p", dnssd);

  if (start_raop_server(server_hw_addr, tcp, udp, debug_log) != 0) {
    LOG("start_raop_server failed");
    return;
  }
  counter = 0;
  compression_type = 0;
}

auto AirPlay::render(const h264_decode_struct *pkt) -> void
{
  if (!obsSource)
    return;

  auto vFrame = vDecoder.decode({pkt->data, pkt->data + pkt->data_len});
  if (!vFrame)
    return;
  obsVFrame->width = vFrame->width;
  obsVFrame->height = vFrame->height;
  obsVFrame->format = vFrame->format;

  for (auto i = 0U; i < vFrame->planes.size(); ++i)
  {
    obsVFrame->data[i] = const_cast<uint8_t *>(vFrame->planes[i].data.data());
    obsVFrame->linesize[i] = vFrame->planes[i].linesize;
  }
  for (auto i = vFrame->planes.size(); i < MAX_AV_PLANES; i++)
  {
    obsVFrame->data[i] = nullptr;
    obsVFrame->linesize[i] = 0;
  }

  // set current time in ns
  obsVFrame->timestamp = pkt->ntp_time_remote * 1'000;
  obs_source_output_video(obsSource, obsVFrame.get());
}

auto AirPlay::getWidth() const -> int
{
  return width;
}

auto AirPlay::getHeight() const -> int
{
  return height;
}

auto AirPlay::name() const -> const char *
{
  return "AirPlay";
}

AirPlay::~AirPlay()
{
  LOG("Stopping...");
  stop_raop_server();
}

auto AirPlay::render(const audio_decode_struct *pkt) -> void
{
  if (!obsSource)
    return;
  auto aFrame = aDecoder.decode({pkt->data, pkt->data + pkt->data_len});
  if (!aFrame)
    return;

  obsAFrame->data[0] = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(aFrame->data.data()));
  for (auto i = 1U; i < MAX_AV_PLANES; i++)
    obsAFrame->data[i] = nullptr;
  obsAFrame->frames = aFrame->data.size() / (aFrame->speakers == SPEAKERS_STEREO ? 2 : 1);
  obsAFrame->speakers = aFrame->speakers;
  obsAFrame->samples_per_sec = aFrame->sampleRate;
  // set current time in ns
  obsAFrame->timestamp = pkt->rtp_time * 1'000;
  obs_source_output_audio(obsSource, obsAFrame.get());
}
