namespace GameshowPro.Mdns;

public record ServiceSearchProfile(string ServiceType, string Protocol, bool AllowLocalhost) : IMdnsServiceSearchProfile;
