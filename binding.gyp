{
  "targets": [
    {
      "include_dirs" : [
        "<!(node -e \"require('nan')\")",
        "<(module_root_dir)/libhydrogen"
      ],
      "libraries": [
        "<(module_root_dir)/libhydrogen/libhydrogen.a"
      ],
      "target_name": "node-libhydrogen-binding",
      "sources": [
        "binding.cc"
      ]
    }
  ]
}
