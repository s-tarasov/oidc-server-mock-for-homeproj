using Microsoft.AspNetCore.DataProtection.Repositories;
using System.Xml.Linq;

namespace NET6PassiveWebApp;

public class ConfigurationXmlRepository : IXmlRepository
{
    private readonly ILogger _logger;
    private readonly IConfiguration _configuration;

    public ConfigurationXmlRepository(ILoggerFactory loggerFactory, IConfiguration configuration)
    {
        _configuration = configuration;
        _logger = loggerFactory.CreateLogger<ConfigurationXmlRepository>();
    }

    public virtual IReadOnlyCollection<XElement> GetAllElements()
    {
        
        var keysXml = _configuration["DataProtectionKeys"];
        var keysDocument = XDocument.Parse(keysXml);
        var elements = keysDocument.Root!.Elements("key").ToArray();
        _logger.LogInformation("key ids:" + string.Join(",", elements.Select(e => e.Attribute("id").Value)));
        return elements;
    }

    void IXmlRepository.StoreElement(XElement element, string friendlyName)
    {
        throw new NotSupportedException();
    }
}
