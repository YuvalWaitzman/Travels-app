const Tour = require('./../models/tourModel');

exports.checkBody = (req, res, next) => {
  if (!(req.body.price && req.body.name)) {
    return res.status(400).json({
      status: 'Failed to create the tour',
      message: 'Tour must contain a name and a price',
    });
  }
  next();
};

exports.getAllTours = (req, res) => {
  res.status(200).json({
    status: 'success',
    requestedAt: req.requestTime,
  });
};

exports.getTour = (req, res) => {
  const id = req.params.id * 1;
};

exports.createTour = (req, res) => {
  res.status(201).json({
    status: 'success',
    data: {
      tour: newTour,
    },
  });
};

exports.updateTour = (req, res) => {
  res.send('success');
};

exports.deleteTour = (req, res) => {
  res.status(204).json({
    status: 'success',
    data: null,
  });
};
