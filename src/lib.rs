use anyhow::{bail, Result};
use esp_idf_svc::{
    eventloop::EspSystemEventLoop,
    hal::peripheral,
    sntp::{EspSntp, SyncStatus},
    sys::ESP_ERR_TIMEOUT,
    wifi::{AuthMethod, BlockingWifi, ClientConfiguration, Configuration, EspWifi},
};

use log::info;

pub struct WIFI {
    wifi: Box<EspWifi<'static>>,
    pass: String,
    ssid: String,
    channel: u8,
    auth: AuthMethod,
    retries: usize,
    sysloop: EspSystemEventLoop,
}

impl WIFI {
    pub fn new(
        ssid: &str,
        pass: &str,
        wifi_channel: u8,
        retries: usize,

        modem: impl peripheral::Peripheral<P = esp_idf_svc::hal::modem::Modem> + 'static,
        sysloop: EspSystemEventLoop,
    ) -> Result<WIFI> {
        let mut auth_method = AuthMethod::WPA2Personal;
        if ssid.is_empty() {
            bail!("Missing WiFi name")
        }
        if pass.is_empty() {
            auth_method = AuthMethod::None;
            info!("Wifi password is empty");
        }

        let mut esp_wifi = EspWifi::new(modem, sysloop.clone(), None)?;

        esp_wifi.set_configuration(&Configuration::Client(ClientConfiguration::default()))?;

        return Ok(WIFI {
            wifi: Box::new(esp_wifi),
            ssid: ssid.to_string(),
            pass: pass.to_string(),
            channel: wifi_channel,
            retries,
            auth: auth_method,
            sysloop: sysloop.clone(),
        });
    }

    pub fn connect(&mut self) -> Result<()> {
        let binding = self.wifi.as_mut();
        let mut wifi = BlockingWifi::wrap(binding, self.sysloop.clone())?;

        if wifi.is_up().is_ok_and(|v| v) {
            info!("Wifi is already up");
            return Ok(());
        }

        info!("Starting wifi...");

        wifi.start()?;

        info!("Scanning...");

        let ap_infos = wifi.scan()?;
        info!("Scanned networks\n {:?}", ap_infos);

        let ours = ap_infos.into_iter().find(|a| a.ssid == self.ssid.as_str());

        let channel = if let Some(ours) = ours {
            info!(
                "Found configured access point {} on channel {}",
                self.ssid, ours.channel
            );
            Some(ours.channel)
        } else {
            info!(
            "Configured access point {} not found during scanning, will go with default channel {}",
            self.ssid, self.channel
        );
            Some(self.channel)
        };

        wifi.set_configuration(&Configuration::Client(ClientConfiguration {
            ssid: self.ssid.as_str().into(),
            password: self.pass.as_str().into(),
            auth_method: self.auth,
            channel,
            ..Default::default()
        }))?;
        // retry and reconnect
        let mut retry = 0;
        loop {
            retry += 1;
            info!("Trying to connect to wifi... {} retry", retry);
            match wifi.connect() {
                Err(e) => {
                    if e.code() == ESP_ERR_TIMEOUT {
                        if retry >= self.retries {
                            bail!(
                                "Failed to connect to wifi {} after {} retries",
                                e,
                                self.retries
                            );
                        }
                        continue;
                    }
                    bail!(e);
                }
                Ok(_) => break,
            }
        }

        info!("Waiting for DHCP lease...");

        wifi.wait_netif_up()?;

        let ip_info = self.wifi.sta_netif().get_ip_info()?;

        info!("Wifi DHCP info: {:?}", ip_info);

        // Create Handle and Configure SNTP
        let ntp = EspSntp::new_default()?;

        // Synchronize NTP
        info!("Synchronizing with NTP Server");
        while ntp.get_sync_status() != SyncStatus::Completed {}
        info!("Time Sync Completed");
        Ok(())
    }
}
