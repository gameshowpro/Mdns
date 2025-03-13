namespace GameshowPro.Mdns;

public record InstanceProperties(string ServiceType, string Protocol, ushort Port) : IMdnsInstanceProperties;
