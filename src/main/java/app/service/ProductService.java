package app.service;

import app.model.Product;
import app.repository.ProductRepository;
import lombok.AllArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Optional;

@Service
@AllArgsConstructor
public class ProductService {
    private final ProductRepository productRepository;

    //Getting all products
    public List<Product> getAllProducts() {
        return productRepository.findAll();
    }

    //Getting product by id
    public Optional<Product> getProductById(Long id) {
        return productRepository.findById(id);
    }

    //saving & updating product
    public Product saveProduct(Product product) {
        return productRepository.save(product);
    }

    //deleting product
    public void deleteProduct(Long id) {
        productRepository.deleteById(id);
    }
}
