// document.addEventListener('DOMContentLoaded', function() {
//     // When the page loads, set the sorting information based on the URL parameter
//     const urlParams = new URLSearchParams(window.location.search);
//     const priceRange = urlParams.get('price_filter') || 'all';
//     updateSortInfo(priceRange);
//     selectRadioButton(priceRange);
// });

document.addEventListener('DOMContentLoaded', function() {
    // 初始化价格筛选信息
    const urlParams = new URLSearchParams(window.location.search);
    const priceRange = urlParams.get('price_filter') || 'all';
    updateSortInfo(priceRange);
    selectRadioButton(priceRange);

    var searchForm = document.getElementById('search-form');
    if (searchForm) {
        searchForm.onsubmit = function() {
            var searchText = document.getElementById('search-input').value;
            var priceFilter = document.querySelector('input[name="price_filter"]:checked').value;
            var searchURL = `/shop?search=${encodeURIComponent(searchText)}&price_filter=${priceFilter}`;
            window.location.href = searchURL;
            return false; // 防止表单的默认提交行为
        };
    }
});

function filterProducts(priceRange) {
    // Send request to the backend
    window.location.href = `/shop?price_filter=${priceRange}`;
}

function updateSortInfo(priceRange) {
    let sortInfoText = 'Current Sorting: ';
    switch(priceRange) {
        case 'all':
            sortInfoText += 'All Prices';
            break;
        case '50-100':
            sortInfoText += 'Prices $50 – $100';
            break;
         case '100-200':
            sortInfoText += 'Prices $100 – $200';
            break;
        case '200-300':
            sortInfoText += 'Prices $200 – $300';
            break;
        case '300-400':
            sortInfoText += 'Prices $300 – $400';
            break;
        case '400-99999':
            sortInfoText += 'Prices $400 and More';
            break;
        default:
            sortInfoText += 'All Prices';
    }
    document.getElementById('sort-info').innerText = sortInfoText;
}

function selectRadioButton(value) {
    // Select the radio button based on the current filter
    let radio = document.querySelector(`input[name='topcoat'][value='${value}']`);
    if (radio) {
        radio.checked = true;
    }
}


function toggleWishlist(productId) {
    // 获取图标元素
    var iconElement = document.querySelector(`div[onclick='toggleWishlist(${productId})']`);
    var isInWishlist = iconElement.classList.contains("fa-heart");

    // 确定请求的 URL
    var url = isInWishlist ? `/remove-from-wishlist/${productId}` : `/add-to-wishlist/${productId}`;

    fetch(url, {
        method: 'GET',
        headers: {
            'Content-Type': 'application/json',
        },
        credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            // 切换图标的类
            iconElement.classList.toggle("fa-heart");
            iconElement.classList.toggle("fa-heart-o");

            // 显示提示信息
            alert(isInWishlist ? "已从心愿单移除" : "已添加到心愿单");
            // 刷新页面
            window.location.reload();
        } else {
            // 如果操作失败，显示错误提示
            alert("操作失败，请重试");
        }
    })
    .catch(error => {
        console.error('Error:', error);
        alert("Please login");
    });
}

// 激活 Bootstrap 工具提示
document.addEventListener('DOMContentLoaded', (event) => {
    var tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'))
    var tooltipList = tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl)
    })
});













