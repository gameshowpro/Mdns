namespace GameshowPro.Mdns;

public record InstanceProperties(string InstanceName, string ServiceType, string Protocol, ushort Port) : IMdnsInstanceProperties;
