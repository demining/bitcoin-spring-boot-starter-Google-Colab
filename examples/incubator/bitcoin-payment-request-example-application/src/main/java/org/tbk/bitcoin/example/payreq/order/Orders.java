package org.tbk.bitcoin.example.payreq.order;

import org.jmolecules.spring.AssociationResolver;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.data.repository.query.Param;
import org.tbk.bitcoin.example.payreq.payment.PaymentRequest;

import java.util.List;
import java.util.Optional;

public interface Orders extends AssociationResolver<Order, Order.OrderId>, PagingAndSortingRepository<Order, Order.OrderId> {

    /**
     * Returns all {@link Order}s with the given {@link Order.Status}.
     *
     * @param status must not be {@literal null}.
     * @return all orders in given status
     */
    List<Order> findByStatus(@Param("status") Order.Status status);

}