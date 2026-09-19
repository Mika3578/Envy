# Configuration Guide

This guide explains how to configure Envy for optimal performance and your specific needs.

## ⚙️ Accessing Settings

### Settings Dialog

1. **Tools → Settings** (or Ctrl+P)
2. **Navigate** through the category tree
3. **Modify** settings as needed
4. **Apply** or **OK** to save changes

### Advanced Settings

For power users:
1. **Tools → Advanced Settings**
2. **Edit** configuration files directly
3. **Backup** before making changes

## 🌐 General Settings

### Interface

- **Language**: Choose from available translations
- **Theme**: Select visual theme/skin
- **Layout**: Customize window layout
- **Tooltips**: Enable/disable help text
- **Sounds**: Configure notification sounds

### Downloads

- **Save Location**: Default download folder
- **File Organization**: Auto-create subfolders
- **Completion Action**: What to do when downloads finish
- **Verification**: Hash checking options

### Uploads

See [transfer-settings.md](transfer-settings.md) for the live Uploads page mapping.

- **Bandwidth Limit**: Global upload cap (`Bandwidth.Uploads`). **Unlimited** (stores `0`; legacy UI token `MAX` still accepted). Effective send rate is still bounded by the connection uplink.
- **Throttle**: Average (soft) vs Maximum (strict) — not a generic “mode”.
- **Max uploads per host**: Simultaneous upload transfers per IPv4 address (`Uploads.MaxPerHost`, default **2**, range 1–64).
- **Queues**: Historical Small/Large/Partial/eDonkey rules; drag reorders immediately. Do not delete.
- **Fair-Use**: opt-in 10% audio/video limit per remote host (`Uploads.FairUseMode`).

## 🔌 Connection Settings

### Network Configuration

#### Basic Settings
- **Networks**: Enable/disable P2P networks
  - BitTorrent: Modern torrent protocol
  - Gnutella2: Advanced P2P network
  - eDonkey2000: Large file network
  - Gnutella: Classic P2P

- **Ports**:
  - TCP Port: Usually 6346 (Gnutella2)
  - UDP Port: Usually 6346 (Gnutella2)
  - Randomize: Let system choose ports

#### Advanced Settings
- **Maximum Connections**: Total peer connections
- **Per Network Limits**: Connections per protocol
- **Timeout Settings**: Connection timeouts
- **Reconnection**: Auto-retry failed connections

### Bandwidth Management

- **Global limits (implemented):**
  - Download cap: Settings → Downloads (`Bandwidth.Downloads`, `0` = unlimited)
  - Upload cap: Settings → Uploads (`Bandwidth.Uploads`, `0` = unlimited)
  - Physical uplink/downlink: Settings → Connection (`Connection.OutSpeed` / `InSpeed`)

- **Per-neighbour G1/G2 pipes (implemented, Advanced — not on the Uploads page):**
  - `Bandwidth.HubIn/Out`, `LeafIn/Out`, `PeerIn/Out`, `UdpOut`
  - These are not a full per-protocol (BT vs ED2K vs HTTP) byte budget

- **Scheduler (implemented separately):**
  - Can overwrite `Bandwidth.Uploads` / `Downloads` on a timetable
  - Not shown as “alt-speed” on the Uploads page

- **Not implemented as transfer settings:** VPN leak protection, bind-interface picker, IPv6 dual-stack, per-torrent connection caps in the qBittorrent sense.

## 🔒 Security Settings

### Content Filtering

- **IP Filters**:
  - Block countries/regions
  - Block specific IP ranges
  - Allow only trusted IPs

- **Content Rules**:
  - Filter by file type
  - Filter by file name patterns
  - Block adult content

- **Spam Protection**:
  - Automated spam detection
  - User reporting system
  - Blacklist management

### Privacy Options

- **Anonymous Mode**:
  - Hide user identity
  - Disable chat features
  - Minimal information sharing

- **Connection Security**:
  - Encrypted connections when possible
  - Certificate validation
  - Secure protocol preferences

## 📁 Library Settings

### File Management

- **Library Folders**:
  - Add/remove watched folders
  - Automatic file detection
  - Exclude patterns

- **File Organization**:
  - Auto-categorization
  - Custom folder structure
  - Metadata management

- **Sharing Options**:
  - Share ratio limits
  - Partial file sharing
  - Private files exclusion

### Hashing and Verification

- **Hash Algorithms**:
  - SHA-1 (default)
  - MD5, Tiger, ED2K
  - Multiple hash support

- **Verification Settings**:
  - Verify on completion
  - Re-verify existing files
  - Hash cache management

## 💬 Communication Settings

### Chat Configuration

- **User Profile**:
  - Username and avatar
  - Away messages
  - Profile information

- **Chat Options**:
  - Timestamps on messages
  - Emoticon support
  - Message history

- **Privacy**:
  - Block unwanted users
  - Ignore lists
  - Private message controls

### IRC Settings

- **Server Configuration**:
  - Default IRC servers
  - Custom server addition
  - Auto-connect options

- **Channel Management**:
  - Auto-join channels
  - Channel passwords
  - Favorite channels

## 🔧 Advanced Settings

### Performance Tuning

#### Memory Management
- **Cache Sizes**: Various internal caches
- **Buffer Sizes**: Network and file buffers
- **Thread Pools**: Worker thread counts

#### CPU Optimization
- **Thread Priority**: Process priority level
- **Background Processing**: When to use CPU
- **Multi-threading**: Enable parallel operations

### Network Advanced

#### Protocol Specific
- **BitTorrent**:
  - DHT enable/disable
  - PEX (Peer Exchange)
  - Magnet link support

- **Gnutella2**:
  - Hub routing preferences
  - Query routing options
  - Network size limits

- **eDonkey2000**:
  - Kad network settings
  - Server list management
  - CryptLayer options

#### Connection Tuning
- **TCP Optimization**:
  - Window sizes
  - Keep-alive settings
  - Congestion control

- **UDP Settings**:
  - Packet sizes
  - Retransmission timeouts
  - Multicast options

### Debugging and Diagnostics

- **Logging Levels**:
  - Error, Warning, Info, Debug
  - Per-component logging
  - Log file rotation

- **Performance Monitoring**:
  - Transfer statistics
  - Memory usage tracking
  - Network diagnostics

## 🎨 Appearance Settings

### Skins and Themes

- **Built-in Themes**:
  - Light and dark themes
  - High contrast options
  - Accessibility themes

- **Custom Skins**:
  - Skin installation
  - Skin management
  - Skin updates

### Window Layout

- **Main Window**:
  - Tab arrangement
  - Panel sizes
  - Toolbar customization

- **Dialog Windows**:
  - Default positions
  - Size preferences
  - Modal behavior

## 🔄 Automation Settings

### Scheduled Tasks

- **Download Scheduling**:
  - Time-based download limits
  - Bandwidth throttling schedules
  - Network availability checks

- **Maintenance Tasks**:
  - Automatic library cleanup
  - Cache clearing schedules
  - Database optimization

### Startup and Shutdown

- **Startup Options**:
  - Auto-start with Windows
  - Minimize to tray
  - Connect to networks automatically

- **Shutdown Behavior**:
  - Complete active downloads
  - Save settings automatically
  - Clean shutdown procedures

## 📊 Statistics and Monitoring

### Data Collection

- **Usage Statistics**:
  - Transfer volumes
  - Network activity
  - File sharing metrics

- **Performance Metrics**:
  - CPU and memory usage
  - Network throughput
  - Error rates

### Privacy Considerations

- **Data Sharing**:
  - Anonymous statistics
  - Crash reporting
  - Feature usage analytics

- **Local Storage**:
  - Log retention policies
  - Cache size limits
  - Temporary file cleanup

## 🔧 Configuration Files

### Manual Editing

**⚠️ Warning**: Backup files before editing manually.

#### Settings.xml
```xml
<Settings>
  <Interface>
    <Language>en</Language>
    <Theme>default</Theme>
  </Interface>
  <Connection>
    <Port>6346</Port>
    <MaxConnections>128</MaxConnections>
  </Connection>
</Settings>
```

#### Advanced Configuration
- Located in `%APPDATA%\Envy\`
- XML format for most settings
- Restart required for some changes

### Backup and Restore

- **Automatic Backups**: Settings backed up on changes
- **Manual Backup**: Tools → Export Settings
- **Restore**: Tools → Import Settings
- **Reset to Defaults**: Tools → Reset Settings

## 🧪 Testing Configuration

### Configuration Validation

1. **Check Settings**: Tools → Validate Configuration
2. **Network Test**: Tools → Test Network
3. **Performance Test**: Tools → Run Diagnostics

### Troubleshooting

- **Reset Problematic Settings**: Individual section reset
- **Configuration Repair**: Automatic repair of corrupted settings
- **Log Analysis**: Check logs for configuration errors

## 📞 Support

### Configuration Help

- **Built-in Help**: Press F1 in settings dialogs
- **Online Documentation**: This guide and [User Guide](guide.md)
- **Community Support**: Forums and IRC channels
- **Issue Reports**: [GitHub Issues](../../issues)

### Common Issues

- **Settings Not Saving**: Check file permissions
- **Network Problems**: Verify port and firewall settings
- **Performance Issues**: Adjust memory and CPU settings
- **UI Problems**: Try different themes or reset layout

---

**Configuration Complete!** ⚙️

Your Envy installation is now configured for optimal performance.

---

**Last Updated:** January 15, 2026
