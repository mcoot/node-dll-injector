{
    "targets": [
        {
            "include_dirs": [
                "<!(node -e \"require('nan')\")"
            ],
            "target_name": "injector",
            "sources": ["injector.cpp"]
        }
    ]
}