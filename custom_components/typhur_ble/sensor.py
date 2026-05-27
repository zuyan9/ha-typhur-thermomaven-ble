"""Sensor platform for Typhur / ThermoMaven BLE."""
import asyncio
import logging
from homeassistant.components.sensor import SensorEntity, SensorDeviceClass, SensorStateClass
from homeassistant.const import UnitOfTemperature, PERCENTAGE, UnitOfTime, SIGNAL_STRENGTH_DECIBELS_MILLIWATT
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.entity import DeviceInfo
from homeassistant.helpers import device_registry as dr
from homeassistant.const import CONF_ADDRESS, CONF_NAME

from homeassistant.components.bluetooth import async_ble_device_from_address
from bleak_retry_connector import BleakClientWithServiceCache, establish_connection
from .blufi_parser import AsyncBlufiClient
from .const import DOMAIN

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry, async_add_entities: AddEntitiesCallback):
    """Set up the sensor platform."""
    address = entry.data[CONF_ADDRESS]
    name = entry.data.get(CONF_NAME, "Typhur Device")
    
    coordinator = TyphurBleCoordinator(hass, address, name)
    hass.data[DOMAIN][entry.entry_id] = coordinator
    
    # Register the Base Station device explicitly
    device_registry = dr.async_get(hass)
    device_registry.async_get_or_create(
        config_entry_id=entry.entry_id,
        identifiers={(DOMAIN, address)},
        connections={(dr.CONNECTION_BLUETOOTH, address)},
        name=f"{name} Base Station",
        manufacturer="Typhur / ThermoMaven",
    )
    
    entities = [
        TyphurTemperatureSensor(coordinator, "Core Temperature", "core", "curTemperature"),
        TyphurTemperatureSensor(coordinator, "Ambient Temperature", "ambient", "curAmbientTemperature"),
        TyphurTemperatureSensor(coordinator, "Target Temperature", "target", "targetTemperature"),
        TyphurBatterySensor(coordinator, "Probe Battery", "probe_battery", "batteryValue"),
        TyphurBatterySensor(coordinator, "Base Station Battery", "base_battery", "baseBatteryValue", is_base=True),
        TyphurTimeSensor(coordinator, "Total Cook Time", "total_cook_time", "totalCookSec"),
        TyphurTimeSensor(coordinator, "Current Cook Time", "current_cook_time", "curCookSec"),
        TyphurTimeSensor(coordinator, "Remaining Time", "remaining_time", "curRemainedSec"),
        TyphurTextSensor(coordinator, "Cooking State", "cooking_state", "cookingState"),
        TyphurTextSensor(coordinator, "Cooking Mode", "cooking_mode", "cookingMode"),
        TyphurTextSensor(coordinator, "Base Station Status", "base_status", "globalStatus", is_base=True),
        TyphurTextSensor(coordinator, "Volume", "volume", "volume", is_base=True),
        TyphurSignalSensor(coordinator, "WiFi RSSI", "wifi_rssi", "wifiRssi", is_base=True)
    ]
    
    for i in range(5):
        entities.append(TyphurTemperatureSensor(coordinator, f"Sensor {i+1}", f"sensor_{i+1}", f"areaTemperature_{i}"))
        
    async_add_entities(entities)
    
    # Start the connection loop
    entry.async_on_unload(coordinator.stop)
    hass.loop.create_task(coordinator.start())

class TyphurBleCoordinator:
    """Manages the BLE connection and data updates."""
    def __init__(self, hass, address, name):
        self.hass = hass
        self.address = address
        self.name = name
        self.data = {}
        self.listeners = []
        self._running = False
        self._client = None

    def add_listener(self, update_callback):
        self.listeners.append(update_callback)
        
    def stop(self):
        self._running = False
        if self._client:
            asyncio.create_task(self._client.disconnect())

    def _disconnected(self, client):
        _LOGGER.error(f"Disconnected from {self.address}")
        self._client = None

    async def start(self):
        self._running = True
        while self._running:
            try:
                _LOGGER.error(f"ATTEMPTING TO CONNECT TO: {self.address}")
                ble_device = async_ble_device_from_address(self.hass, self.address)
                if not ble_device:
                    _LOGGER.warning(f"BLE device {self.address} not found in HA cache. Falling back to bleak scanner...")
                    from bleak import BleakScanner
                    ble_device = await BleakScanner.find_device_by_address(self.address, timeout=10.0)
                    
                if not ble_device:
                    _LOGGER.warning(f"BLE device {self.address} not found by fallback scanner either.")
                    await asyncio.sleep(10)
                    continue

                _LOGGER.error(f"Calling establish_connection for {self.address}")
                self._client = await establish_connection(
                    BleakClientWithServiceCache, 
                    ble_device,
                    self.name,
                    self._disconnected,
                    use_services_cache=True,
                    ble_device_callback=lambda: ble_device
                )
                
                if not self._client.services:
                    await self._client.get_services()
                    
                try:
                    if hasattr(self._client, "_backend") and hasattr(self._client._backend, "_acquire_mtu"):
                        await self._client._backend._acquire_mtu()
                    elif hasattr(self._client, "_acquire_mtu"):
                        await self._client._acquire_mtu()
                except Exception as e:
                    _LOGGER.error(f"Failed to acquire MTU: {e}")
                
                _LOGGER.error(f"establish_connection returned for {self.address}, MTU: {getattr(self._client, 'mtu_size', 'unknown')}")
                blufi = AsyncBlufiClient(self._client, self.address, self._on_data)
                await blufi.setup()
                _LOGGER.error(f"Blufi setup complete for {self.address}")
                
                while self._running and self._client.is_connected:
                    await asyncio.sleep(5)
                    
            except Exception as e:
                _LOGGER.error(f"Error communicating with {self.address}: {e}")
                if self._client:
                    await self._client.disconnect()
                await asyncio.sleep(5) # Reconnect backoff

    def _on_data(self, payload):
        try:
            _LOGGER.error(f"RAW PAYLOAD RECEIVED: {payload}")
            
            # WT10 payload format (binary struct parsed into dict)
            if "probe_id" in payload:
                cur_temp = payload.get("cur_temp")
                self.data["curTemperature"] = (cur_temp / 10.0) if cur_temp not in (None, 0, 65535) else None
                
                cur_amb = payload.get("ambient_temp")
                self.data["curAmbientTemperature"] = (cur_amb / 10.0) if cur_amb not in (None, 0, 65535) else None
                
                self.data["batteryValue"] = payload.get("battery_level")
                
                for listener in self.listeners:
                    listener()
                return

            # WT11 payload format (JSON)
            cmd_data = payload.get("cmdData")
            if isinstance(cmd_data, dict):
                self.data["globalStatus"] = cmd_data.get("globalStatus")
                self.data["baseBatteryValue"] = cmd_data.get("batteryValue")
                self.data["wifiRssi"] = cmd_data.get("wifiRssi")
                self.data["volume"] = cmd_data.get("volume")
                
                probes = cmd_data.get("probes", [])
                if probes:
                    probe = probes[0]
                    
                    cur_temp = probe.get("curTemperature")
                    self.data["curTemperature"] = (cur_temp / 10.0) if cur_temp not in (None, 0, 65535, -1) else None

                    cur_amb = probe.get("curAmbientTemperature")
                    self.data["curAmbientTemperature"] = (cur_amb / 10.0) if cur_amb not in (None, 0, 65535, -1) else None
                    
                    self.data["batteryValue"] = probe.get("batteryValue")
                    self.data["cookingState"] = probe.get("cookingState")
                    self.data["cookingMode"] = probe.get("cookingMode")
                    self.data["totalCookSec"] = probe.get("totalCookSec")
                    self.data["curCookSec"] = probe.get("curCookSec")
                    self.data["curRemainedSec"] = probe.get("curRemainedSec")
                    
                    # Target Temp
                    set_params = probe.get("setParams", [])
                    if set_params and isinstance(set_params, list):
                        set_temp = set_params[0].get("setTemperature")
                        self.data["targetTemperature"] = (set_temp / 10.0) if set_temp not in (None, 0, 65535, -1) else None
                    
                    area = probe.get("areaTemperature", [])
                    for i, val in enumerate(area):
                        self.data[f"areaTemperature_{i}"] = (val / 10.0) if val not in (None, 0) else None
                        
                    for listener in self.listeners:
                        listener()
                    return
        except Exception as e:
            _LOGGER.error(f"Error parsing data: {e}")

class TyphurTemperatureSensor(SensorEntity):
    def __init__(self, coordinator, name, key, data_key):
        self.coordinator = coordinator
        self._name = name
        self._key = key
        self.data_key = data_key
        self._attr_unique_id = f"{coordinator.address}_{key}"
        self._attr_device_class = SensorDeviceClass.TEMPERATURE
        self._attr_state_class = SensorStateClass.MEASUREMENT
        # The BLE payload sends raw Fahrenheit * 10. By claiming NativeUnit is F,
        # HA will automatically convert to the user's preferred unit (C or F).
        self._attr_native_unit_of_measurement = UnitOfTemperature.FAHRENHEIT

    @property
    def name(self):
        return f"{self.coordinator.name} {self._name}"

    @property
    def native_value(self):
        return self.coordinator.data.get(self.data_key)

    @property
    def device_info(self):
        return DeviceInfo(
            identifiers={(DOMAIN, f"{self.coordinator.address}_probe")},
            name=f"{self.coordinator.name} Probe",
            manufacturer="Typhur / ThermoMaven",
            via_device=(DOMAIN, self.coordinator.address),
        )

    async def async_added_to_hass(self):
        self.coordinator.add_listener(self.async_write_ha_state)

class TyphurBatterySensor(SensorEntity):
    def __init__(self, coordinator, name, key, data_key, is_base=False):
        self.coordinator = coordinator
        self._name = name
        self._key = key
        self.data_key = data_key
        self.is_base = is_base
        self._attr_unique_id = f"{coordinator.address}_{key}"
        self._attr_device_class = SensorDeviceClass.BATTERY
        self._attr_state_class = SensorStateClass.MEASUREMENT
        self._attr_native_unit_of_measurement = PERCENTAGE

    @property
    def name(self):
        return f"{self.coordinator.name} {self._name}"

    @property
    def native_value(self):
        return self.coordinator.data.get(self.data_key)

    @property
    def device_info(self):
        if self.is_base:
            return DeviceInfo(
                identifiers={(DOMAIN, self.coordinator.address)},
            )
        return DeviceInfo(
            identifiers={(DOMAIN, f"{self.coordinator.address}_probe")},
            name=f"{self.coordinator.name} Probe",
            manufacturer="Typhur / ThermoMaven",
            via_device=(DOMAIN, self.coordinator.address),
        )

    async def async_added_to_hass(self):
        self.coordinator.add_listener(self.async_write_ha_state)

class TyphurTimeSensor(SensorEntity):
    def __init__(self, coordinator, name, key, data_key):
        self.coordinator = coordinator
        self._name = name
        self._key = key
        self.data_key = data_key
        self._attr_unique_id = f"{coordinator.address}_{key}"
        self._attr_device_class = SensorDeviceClass.DURATION
        self._attr_state_class = SensorStateClass.MEASUREMENT
        self._attr_native_unit_of_measurement = UnitOfTime.SECONDS

    @property
    def name(self):
        return f"{self.coordinator.name} {self._name}"

    @property
    def native_value(self):
        return self.coordinator.data.get(self.data_key)

    @property
    def device_info(self):
        return DeviceInfo(
            identifiers={(DOMAIN, f"{self.coordinator.address}_probe")},
            name=f"{self.coordinator.name} Probe",
            manufacturer="Typhur / ThermoMaven",
            via_device=(DOMAIN, self.coordinator.address),
        )

    async def async_added_to_hass(self):
        self.coordinator.add_listener(self.async_write_ha_state)

class TyphurTextSensor(SensorEntity):
    def __init__(self, coordinator, name, key, data_key, is_base=False):
        self.coordinator = coordinator
        self._name = name
        self._key = key
        self.data_key = data_key
        self.is_base = is_base
        self._attr_unique_id = f"{coordinator.address}_{key}"

    @property
    def name(self):
        return f"{self.coordinator.name} {self._name}"

    @property
    def native_value(self):
        return self.coordinator.data.get(self.data_key)

    @property
    def device_info(self):
        if self.is_base:
            return DeviceInfo(
                identifiers={(DOMAIN, self.coordinator.address)},
            )
        return DeviceInfo(
            identifiers={(DOMAIN, f"{self.coordinator.address}_probe")},
            name=f"{self.coordinator.name} Probe",
            manufacturer="Typhur / ThermoMaven",
            via_device=(DOMAIN, self.coordinator.address),
        )

    async def async_added_to_hass(self):
        self.coordinator.add_listener(self.async_write_ha_state)

class TyphurSignalSensor(SensorEntity):
    def __init__(self, coordinator, name, key, data_key, is_base=False):
        self.coordinator = coordinator
        self._name = name
        self._key = key
        self.data_key = data_key
        self.is_base = is_base
        self._attr_unique_id = f"{coordinator.address}_{key}"
        self._attr_device_class = SensorDeviceClass.SIGNAL_STRENGTH
        self._attr_state_class = SensorStateClass.MEASUREMENT
        self._attr_native_unit_of_measurement = SIGNAL_STRENGTH_DECIBELS_MILLIWATT

    @property
    def name(self):
        return f"{self.coordinator.name} {self._name}"

    @property
    def native_value(self):
        return self.coordinator.data.get(self.data_key)

    @property
    def device_info(self):
        if self.is_base:
            return DeviceInfo(
                identifiers={(DOMAIN, self.coordinator.address)},
            )
        return DeviceInfo(
            identifiers={(DOMAIN, f"{self.coordinator.address}_probe")},
            name=f"{self.coordinator.name} Probe",
            manufacturer="Typhur / ThermoMaven",
            via_device=(DOMAIN, self.coordinator.address),
        )

    async def async_added_to_hass(self):
        self.coordinator.add_listener(self.async_write_ha_state)
