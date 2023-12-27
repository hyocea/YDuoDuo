$(document).ready(function() {
    $('.quantity-input').on('change', function() {
        var productId = $(this).data('product-id');
        var quantity = $(this).val();

        $.ajax({
            url: '/update-cart/' + productId,
            type: 'POST',
            contentType: 'application/json',
            data: JSON.stringify({ quantity: quantity }),
            dataType: 'json',
            success: function(response) {
                console.log(response);
            },
            error: function(xhr, status, error) {
                console.error("An error occurred: " + status + ", " + error);
            }
        });
    });
});

function updateQuantity(productId, action) {
    var quantityInput = document.querySelector(`.quantity-input[data-product-id="${productId}"]`);
    var currentQuantity = parseInt(quantityInput.value);

    if (action === 'inc') {
        currentQuantity += 1;
    } else if (action === 'dec' && currentQuantity > 1) {
        currentQuantity -= 1;
    } else {
        // 如果数量小于1，则不执行任何操作
        return;
    }

    $.ajax({
        url: `/update-cart/${productId}`,
        type: 'POST',
        contentType: 'application/json',
        data: JSON.stringify({quantity: currentQuantity}),
        success: function(response) {
            if (response.status === 'success') {
                quantityInput.value = currentQuantity;
            }
        },
        error: function(error) {
            console.log('Error:', error);
        }
    });
}
