document.addEventListener('DOMContentLoaded', function() {
    const selectAllCheckbox = document.getElementById('select-all-logs');
    if (selectAllCheckbox) {
        selectAllCheckbox.addEventListener('click', function(e) {
            const checkboxes = document.querySelectorAll('input[name="log_ids[]"]');
            checkboxes.forEach(function(checkbox) {
                checkbox.checked = e.target.checked;
            });
        });
    }
});
