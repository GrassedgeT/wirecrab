//! 网络接口设备管理

use anyhow::Result;
use pcap::Device;

/// 获取所有可用的网络设备
pub fn list_devices() -> Result<Vec<Device>> {
    Ok(Device::list()?)
}

/// 根据名称查找设备
pub fn find_device_by_name(name: &str) -> Result<Device> {
    let devices = list_devices()?;
    
    devices
        .into_iter()
        .find(|d| d.name == name)
        .ok_or_else(|| anyhow::anyhow!("未找到名为 {} 的网络设备", name))
}

/// 获取默认设备（第一个非回环设备）
pub fn get_default_device() -> Result<Device> {
    let devices = list_devices()?;
    
    // 优先选择非回环、非any接口
    for device in &devices {
        if !device.name.contains("lo") && 
           !device.name.contains("any") &&
           !device.name.contains("nflog") &&
           !device.name.contains("nfqueue") {
            return Ok(device.clone());
        }
    }
    
    // 如果没有找到，返回第一个设备
    devices
        .into_iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("未找到可用的网络设备"))
}

/// 设备信息
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<String>,
}

impl From<Device> for DeviceInfo {
    fn from(device: Device) -> Self {
        let mut addresses = Vec::new();
        
        // 收集所有IP地址
        for addr in &device.addresses {
            // TODO: 正确解析地址格式
            addresses.push(format!("{:?}", addr));
        }
        
        DeviceInfo {
            name: device.name,
            description: device.desc,
            addresses,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_devices() {
        // 这个测试可能需要root权限
        match list_devices() {
            Ok(devices) => {
                println!("找到 {} 个网络设备", devices.len());
                for device in devices {
                    println!("设备: {}", device.name);
                }
            }
            Err(e) => {
                println!("无法列出设备（可能需要root权限）: {}", e);
            }
        }
    }
}