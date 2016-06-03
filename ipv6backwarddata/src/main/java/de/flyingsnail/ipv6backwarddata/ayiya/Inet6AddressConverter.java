package de.flyingsnail.ipv6backwarddata.ayiya;

import java.net.Inet6Address;
import java.net.UnknownHostException;

import javax.persistence.AttributeConverter;
import javax.persistence.Converter;

@Converter(autoApply = true)
public class Inet6AddressConverter implements AttributeConverter<Inet6Address, String> {

  @Override
  public String convertToDatabaseColumn(Inet6Address attribute) {
    return attribute.getHostAddress();
  }

  @Override
  public Inet6Address convertToEntityAttribute(String dbData) {
    // TODO Auto-generated method stub
    try {
      return (Inet6Address)Inet6Address.getByName(dbData);
    } catch (UnknownHostException e) {
      throw new IllegalArgumentException("Cannot convert to Inet6Addres: " + dbData);
    }
  }

}
