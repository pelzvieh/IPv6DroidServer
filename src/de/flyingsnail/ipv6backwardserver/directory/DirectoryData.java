package de.flyingsnail.ipv6backwardserver.directory;

import javax.persistence.EntityManager;
import javax.persistence.criteria.CriteriaBuilder;

/**
 * This object encapsulates the data access to common data used in the directory service.
 * @author pelzi
 *
 */
public interface DirectoryData {

  /**
   * @return the criteriaBuilder
   */
  CriteriaBuilder getCriteriaBuilder();

  /**
   * @return the entityManager
   */
  EntityManager getEntityManager();

}