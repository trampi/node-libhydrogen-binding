{
  "targets": [
    {
      "include_dirs" : [
        "<!(node -e \"require('nan')\")",
        "<(module_root_dir)/libhydrogen"
      ],
      "libraries": [
      ],
      "target_name": "node-libhydrogen-binding",
      "sources": [
        "binding.cc"
      ]
    }
  ]
}
